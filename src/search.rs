use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use crate::adapters::{Adapted, Adapter, Direct};
use crate::controls::Control;
use crate::ldap::Ldap;
use crate::parse_filter;
use crate::protocol::LdapOp;
use crate::result::{LdapError, LdapResult, Result};

use tokio::sync::{mpsc, Mutex};
use tokio::time;

use lber::common::TagClass;
use lber::structure::StructureTag;
use lber::structures::{Boolean, Enumerated, Integer, OctetString, Sequence, Tag};

/// Possible values for search scope.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scope {
    /// Base object; search only the object named in the base DN.
    Base = 0,
    /// Search the objects immediately below the base DN.
    OneLevel = 1,
    /// Search the object named in the base DN and the whole subtree below it.
    Subtree = 2,
}

/// Possible values for alias dereferencing during search.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DerefAliases {
    /// Never dereference.
    Never = 0,
    /// Dereference while retrieving objects according to search scope.
    Searching = 1,
    /// Dereference while finding the base object.
    Finding = 2,
    /// Always dereference.
    Always = 3,
}

impl Default for DerefAliases {
    fn default() -> Self {
        DerefAliases::Never
    }
}

#[derive(Debug)]
pub enum SearchItem {
    Entry(StructureTag),
    Referral(StructureTag),
    Done(LdapResult),
}

/// Wrapper for the internal structure of a result entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResultEntry(pub StructureTag, pub Vec<Control>);

impl ResultEntry {
    #[doc(hidden)]
    pub fn new(st: StructureTag) -> ResultEntry {
        ResultEntry(st, vec![])
    }

    /// Returns true if the enclosed entry is a referral.
    pub fn is_ref(&self) -> bool {
        self.0.id == 19
    }

    /// Returns true if the enclosed entry is an intermediate message.
    pub fn is_intermediate(&self) -> bool {
        self.0.id == 25
    }
}

/// Additional parameters for the Search operation.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SearchOptions {
    pub deref: DerefAliases,
    pub typesonly: bool,
    pub timelimit: i32,
    pub sizelimit: i32,
}

impl SearchOptions {
    /// Create an instance of the structure with default values.
    pub fn new() -> Self {
        SearchOptions {
            ..Default::default()
        }
    }

    /// Set the method for dereferencing aliases.
    pub fn deref(mut self, d: DerefAliases) -> Self {
        self.deref = d;
        self
    }

    /// Set the indicator of returning just attribute names (`true`) vs. names and values (`false`).
    pub fn typesonly(mut self, typesonly: bool) -> Self {
        self.typesonly = typesonly;
        self
    }

    /// Set the time limit, in seconds, for the whole search operation.
    ///
    /// This is a server-side limit of the elapsed time for performing the operation, _not_ a
    /// network timeout for retrieving result entries or the result of the whole operation.
    pub fn timelimit(mut self, timelimit: i32) -> Self {
        self.timelimit = timelimit;
        self
    }

    /// Set the size limit, in entries, for the whole search operation.
    pub fn sizelimit(mut self, sizelimit: i32) -> Self {
        self.sizelimit = sizelimit;
        self
    }
}

/// Parsed search result entry.
///
/// While LDAP attributes can have a variety of syntaxes, they're all returned in
/// search results as octet strings, without any associated type information. A
/// general-purpose result parser could leave all values in that format, but then
/// retrieving them from user code would be cumbersome and tedious.
///
/// For that reason, the parser tries to convert every value into a `String`. If an
/// attribute can contain unconstrained binary strings, the conversion may fail. In that case,
/// the attribute and all its values will be in the `bin_attrs` hashmap. Since it's
/// possible that a particular set of values for a binary attribute _could_ be
/// converted into UTF-8 `String`s, the presence of of such attribute in the result
/// entry should be checked for both in `attrs` and `bin_atrrs`.
#[derive(Debug, Clone)]
pub struct SearchEntry {
    /// Entry DN.
    pub dn: String,
    /// Attributes.
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl SearchEntry {
    /// Parse raw BER data and convert it into attribute map(s).
    ///
    /// __Note__: this function will panic on parsing error.
    pub fn construct(re: ResultEntry) -> SearchEntry {
        let mut tags =
            re.0.match_id(4)
                .and_then(|t| t.expect_constructed())
                .expect("entry")
                .into_iter();
        let dn = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("dn");
        let mut attr_vals = HashMap::new();
        let mut bin_attr_vals = HashMap::new();
        let attrs = tags
            .next()
            .expect("element")
            .expect_constructed()
            .expect("attrs")
            .into_iter();
        for a_v in attrs {
            let mut part_attr = a_v
                .expect_constructed()
                .expect("partial attribute")
                .into_iter();
            let a_type = String::from_utf8(
                part_attr
                    .next()
                    .expect("element")
                    .expect_primitive()
                    .expect("octet string"),
            )
            .expect("attribute type");
            let mut any_binary = false;
            let values = part_attr
                .next()
                .expect("element")
                .expect_constructed()
                .expect("values")
                .into_iter()
                .map(|t| t.expect_primitive().expect("octet string"))
                .filter_map(|s| {
                    if let Ok(s) = std::str::from_utf8(s.as_ref()) {
                        return Some(s.to_owned());
                    }
                    bin_attr_vals
                        .entry(a_type.clone())
                        .or_insert_with(|| vec![])
                        .push(s);
                    any_binary = true;
                    None
                })
                .collect::<Vec<String>>();
            if any_binary {
                bin_attr_vals.get_mut(&a_type).expect("bin vector").extend(
                    values
                        .into_iter()
                        .map(String::into_bytes)
                        .collect::<Vec<Vec<u8>>>(),
                );
            } else {
                attr_vals.insert(a_type, values);
            }
        }
        SearchEntry {
            dn,
            attrs: attr_vals,
            bin_attrs: bin_attr_vals,
        }
    }
}

/// Possible states of a `SearchStream`.
///
/// ## `SearchStream` call/state diagram
///
/// <div>
/// <img src="data:image/png;base64,
/// iVBORw0KGgoAAAANSUhEUgAAAWgAAAFQCAYAAACSzOQVAAAABHNCSVQICAgIfAhk
/// iAAAAAlwSFlzAAAN1wAADdcBQiibeAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3Nj
/// YXBlLm9yZ5vuPBoAACAASURBVHic7d17VFRlowbwZxyQi2CASsrNgMRugoIYlBiC
/// iglZaDMoSJEdvJw0TV0aX3nDTD81rdX5rLS+LNM0O7HyVmiKqaRgIqQJXgA/LuIF
/// RSRuNsN7/vCwV9OAAgJ7jzy/tViL2fvd+72Aj+9+955BJYQQICIixekkdwOIiKhh
/// DGgiBYqNjcWXX34pdzNIZgxoIgXKycnBpUuX5G4GyYwBTdREq1evxvr16/Hee+9h
/// 0KBBGDVqFDIzMw3KXLp0CTNnzkRQUBBGjhyJrVu3GuwbN24cTp06JW0rLCxEVFQU
/// srOzAQBvvPEGtFotcnNzsWnTJmi1Wmi1WqSnp7dPJ0lRGNBETXT06FG89dZbKCws
/// xPz58yGEQFRUFOrvs5eXl2Pw4ME4e/YsEhISEBUVhWnTpmHTpk0AgJ49e6Jv374Y
/// N24cqqqqoNfrMWHCBHTp0gWPPvooAGDkyJHQaDRwcHCAt7c3NBoNNBoNnJ2dZes3
/// yUfFpziImkar1SI/Px/Hjh0DAJw8eRLe3t4oLi6Gk5MTVq9ejTVr1uDcuXOwtLQE
/// ALz//vv44osvcOLECQCAXq/H8OHD8fDDD8PZ2Rnbtm1Deno6rK2tDery9/eHRqPB
/// 3Llz27eTpChmcjeAyJR4e3tL3/fs2RMAUFpaCicnJ2RmZsLKygqLFi2SyuTn5yMn
/// JwdCCKhUKqjVamzatAkDBgxAVVUVjhw5YhTORPUY0ETNYGFhIX2vUqkAQFriqKio
/// gL29Pezt7aUy9vb28PX1RV1dHdRqtXScSqWCEAKdOnGVkRrHgCZqJV5eXrhx4wbm
/// zZvXaBm9Xo+YmBgMGzYMLi4u0Gg0DS5xmJmZQa/Xt3WTSeH43zdRK4mJiUFqairW
/// rVsnzarPnTsn3SQEgMTERBQUFGDt2rVITEyEra0tXnvtNaNzeXh4YN++fSgrK2u3
/// 9pPyMKCJWom3tze+/vprLF68GLa2tnBwcED//v2lx+r27t2LFStWYPPmzbC1tYW5
/// uTk2b96MpKQkbNiwweBcb7/9NqqqquDs7AyVSoXvvvtOhh6R3PgUB1EbKC4uRmVl
/// JXr37m2wbk3UHAxoIiKF4hIHEZFCMaCJiBSKAU1EpFAMaCIihWJAExEpFAOaiEih
/// GNBERArFgCYiUigGNBGRQvHT7KjDqP940I6Obx42HZxBExEpFGfQ1OF01BkkryBM
/// D2fQREQKxYAmIlIoBjQRkUIxoImIFIoBTUSkUAxoIiKFYkATESkUn4MmakeZmZnI
/// yclB165dERAQAAcHB7mbRArGgCZqJ4MHD0ZaWhoefvhhVFZWoqKiAhs3bkRERITc
/// TSOF4hIHUTuJjo7GpUuXkJ2djQsXLiAyMhIvvfQSdDqd3E0jhVKJjvq+V+pw6t/q
/// rJRf+d27dyM8PBy5ubnw8PBo8/qU1n+6O86giWSSlZUFe3t7ODs7y90UUigGNJEM
/// ioqKsHLlSqxcuRIWFhZyN4cUiksc1GEo5RK/oqICwcHB6Nu3LzZt2tRunzKnlP5T
/// 0zGgqcNQQkDV1tYiPDwcarUaO3bsQOfOndutbiX0n5qHj9kRtRO9Xo/Y2FhUVlZi
/// 79697RrOZJo4g6YOQ+4Z5Msvv4yff/4ZSUlJeOCBB6TtTk5OsLS0bPP65e4/NR8D
/// mjoMuQOqS5cuqKqqMtp+8OBBBAUFtXn9cvefmo8BTR1GRw+ojt5/U8TH7IiIFIoB
/// TUSkUAxoIiKFYkATESkUA5qISKEY0ERECsWAJiJSKAY0EZFCMaCJiBSKAU1EpFD8
/// NDvqcNrr85eJ7hVn0ERECsUZNHUY/JAgMjWcQRMRKRQDmohIoRjQREQKxYAmIlIo
/// BjQRkUIxoInaSVBQULv87UG6f/BvEhK1E/5NQGouzqCJiBSKAU1EpFAMaCIihWJA
/// ExEpFAOaiEihGNBERArFgCYiUigGNBGRQjGgiYgUigFNRKRQDGgiIoViQBMRKRQD
/// mohIoRjQREQKxYAmIlIoBjQRkUIxoImIFIoBTUSkUAxoIiKFYkATESkUA5qISKEY
/// 0ERECmUmdwOI7jfFxcWIi4trdP/w4cONtm3YsAHOzs5t2CoyRQxoolbm7OwMCwsL
/// 7Nq1q8H9P/30k8Hr8PBwhjM1SCWEEHI3guh+c/z4cfj7+6Mp/7zS0tIwaNCgdmgV
/// mRquQRO1AT8/P4waNequ5cLDwxnO1CjOoInaSFNm0Zw9051wBk3URu42i+bsme6G
/// M2iiNnSnWTRnz3Q3nEETtaHGZtGcPVNTcAZN1MaOHTtmFMbp6enw9/eXqUVkKjiD
/// Jmpj/v7+CA8Pl16Hh4cznKlJGNB03zlx4gRiYmLkboaBxYsXQ6VSAQAWLFggc2uU
/// TQiBTZs2YfLkydBqtTh58qRRmenTp2P//v0trkOn00Gr1SInJ6fZx37xxRf45z//
/// 2eK6m4MBbYLmz5+PxMTENq1jx44diIiIaNM62kppaek9/eNtC/Vr0UpZe46NjcWX
/// X34pdzMatG3bNkybNg2enp4YNmwYHBwcjMqkpqaiuLi4xXXU1dXhp59+wo0bN5p9
/// bFZWFlJTU1tcd3Pwrd4m6MKFC+jcuXOb1nHt2rUGZy6mYPjw4SgpKZG7GUYWLlwo
/// dxMkOTk56Nevn9zNaNDBgwcRFhaGuXPnNlomIyPjnuro3Lkzrl+/fk/naA+cQSvM
/// pk2bEBoaCl9fX0RERCApKUnat2rVKmi1Whw6dAgpKSnQarXQarUGZX788UdER0fD
/// 398fAQEBSEhIQEVFhUEdp06dglarxcWLF/Hyyy/D19cXMTExuHHjBpKTk6HVarF2
/// 7VqUlpZKdbT1jL01/P7771J7G1riOH36NLRaLX799VeEh4cjICAAK1euNHgEbs6c
/// OUhKSsLcuXPh5+cHrVaLoqIig/Pk5OQgPj4eAQEBeOGFF/Dzzz8b1TVr1iz88MMP
/// +Ne//oXAwEA888wzuHr16h3XnlevXo3169fjvffew6BBgzBq1ChkZmYalLl06RJm
/// zpyJoKAgjBw5Elu3bjXYN27cOJw6dUraVlhYiKioKGRnZwMA3njjDWi1WuTm5mLT
/// pk3SeKWnp99ldNve6tWrodVqsWvXLhw9elRq218nCrNnz5a2N3SV1JSf3/jx46Vz
/// NLTEUVlZiYSEBDz99NPw9/dHbGwszp49a1Tu888/R2BgIIYNG4aUlJRWGAFjnEEr
/// yN69ezFp0iR8+OGH6NOnD86dO4fc3Fxp/1NPPYXevXvj0qVLMDMzg0ajAQA88sgj
/// Bufo168fYmNjcevWLSxZsgRnz57F//7v/0plrly5gm3btuHixYsIDg7G8OHDkZaW
/// htLSUnh6ekKj0eDAgQPIz8+X6nB0dGynUWg5R0dHaDQanDhxAmvWrDHaf/XqVWzb
/// tg2lpaV47bXXUFhYiDlz5sDb2xthYWEAgD179mDz5s2YNm0aFi5ciAULFmDq1KnY
/// sWMHAOD8+fMIDAzE2LFjsXjxYvz+++8YNWoUUlJSDJYukpOTcfDgQXTr1g3x8fGo
/// qKjAmTNn7vjGlaNHj+LAgQOIjo7G/PnzsXbtWkRFRSEnJwcqlQrl5eUYPHgwvLy8
/// kJCQgMuXL2PatGnQ6XSIiYlBz5490bdvX4wbNw7p6emwsLDAhAkT4OnpiUcffRQA
/// MHLkSNy8eRMZGRnw9vbG6NGjAUARH9YUGBgIV1dXXL16FXV1dQ3+7oWFhaG8vBzT
/// p0/HiBEjEBISYnCOu/38AGDs2LH4888/ER0djddff92oHXPnzkVqaiqWLl0KS0tL
/// HD16FEVFRfDy8pLKHD16FHZ2dvjHP/6BLVu2QKPRoKCgANbW1q07KIIU49133xU+
/// Pj53LTdhwgQxceLEJp1z3759Qq1WC71eb7ANgFi3bl2jx33++efCzc2tSXUoza5d
/// u4SlpaXR9gMHDggA4ujRo9K2IUOGiH/84x/S6379+okJEyZIr7/55hvRtWtX6XV8
/// fLwYPHiwqKurk7ZNmTJFREVFGdT12GOPif79+xuM+91oNBoxcOBA6fVvv/0mAIji
/// 4mIhhBDvvfeecHFxEdXV1VKZNWvWiP79+0uvdTqdGDp0qIiPjxeLFi0Sjz/+uKis
/// rDSqa+DAgeKf//xnk9vWnuLi4sRLL710xzIeHh5i/fr1Rtvv9vOrV1tbKwCIQ4cO
/// Ge178sknxYIFCxqt+4033hAuLi7izz//FEIIce3aNQFApKWl3bHNLcEZtIIMHToU
/// CxcuxODBg/H8889LSx3NUVhYiFWrViEjIwPV1dWorq6GXq9HeXk57O3tDcrWz546
/// mr+uvfbq1QulpaUG+729vaXve/bsiZs3b+LWrVvo3LkzMjMzoVarkZCQIJU5f/48
/// rl69alTPc889h06dmreK+Pe6gds3PZ2cnJCZmQkrKyssWrRIKpOfn4+cnBwIIaBS
/// qaBWq7Fp0yYMGDAAVVVVOHLkSOvP6hTuTj+/phgxYgRWrlyJ7OxsPPvsswgLC4OT
/// k5NBmcceewxmZrfj08HBARYWFka/R62Ba9AKEhAQgMzMTISEhGDLli3w8/PDrFmz
/// mnz8rVu3EBISgpKSEixbtgxbt27F0qVLAdx+rOjvevTo0WptNyUWFhbS9yqVyuht
/// 2H/9h1z/aFx9mYqKCnTr1g329vbS17BhwzB16lSjeloyvn9v29/r/mu99vb28PX1
/// xaJFi1BXV2dwXH2/mvsfxP3gTj+/pkhMTMS2bdvQvXt3vPXWW/D09MSePXsMyvz1
/// 51RfT3PqaCrOoBXmscceQ2JiIhITE/Hxxx9jxowZWLVqlcE/NDMzswYDNzs7G+fP
/// n0d6ero0W/7ll18arav+l7ch5ubmDdbR0Xl5ecHJyQnz5s2Tpe4bN27csW69Xo+Y
/// mBgMGzYMLi4u0Gg0SE9PN5pFm5mZQa/Xt3WTTVZ4eDjCw8Px4YcfYvTo0Vi3bh1G
/// jBjR7u3oeP+9KlhKSop0V1kIgUuXLqFnz55GsyAPDw8cOXLE6DlQBwcHqFQqHD58
/// GMDt5Y7ly5e3qC0eHh64fPkyUlNTDWZnHV1cXBw2bNiA5ORkadvx48exc+fONq87
/// JiYGqampWLdunTRbO3fuHDZt2iSVSUxMREFBAdauXYvExETY2tritddeMzqXh4cH
/// 9u3bh7KysjZvt6nZsmWLNC61tbUoKyuT7SYqA1pBTp48CV9fX3Tr1g0PPvggPv30
/// U3z66adG5aZOnSrdmVepVHj33XcBAK6urli8eDHGjh0LZ2dn9O/fHxMmTGhRWwID
/// AzFt2jSMGTMGarUaoaGh99S39hAYGAiVSoXw8HDU1NRIl/qt+a6vyMhILFu2DFFR
/// UbC3t4etrS1GjBiBixcvtlodjfH29sbXX3+NxYsXw9bWFg4ODujfv7/0WN3evXux
/// YsUKbN68Gba2tjA3N8fmzZuRlJSEDRs2GJzr7bffRlVVFZydnaFSqfDdd9+1efvv
/// 1VdffSX9TPPy8hAfHw+VSgU3N7cmn2P+/PlQqVTSEkVQUBBUKpXB7Hjjxo3o0aMH
/// XFxc0KNHD3Tq1Alvv/12q/enKfhhSQpz69Yt5Ofnw9zcHK6urjA3N2/2Oa5fv46S
/// khJ4eHjAysqqDVpJQgjk5+dDpVLB1dVVumHUXoqLi1FZWYnevXsbrYfSvbtx4waK
/// iorQvXt36WatHBjQREQKxSUOIiKFYkATtZH69c07fQUFBcndTFIwBjQRkUJxDZqI
/// SKE4gyYiUigGNBGRQjGgiYgUigFNRKRQDGgiIoXip9m1ozt9elxHIteDQxz/2zj+
/// 8mrO+HMGTUSkUJxBy6CjPnqulBkUx19eHP+m4wyaiEihGNBERArFgCYiUigGNBGR
/// QjGgiYgUigFNRKRQDGgiIoVqteeg9Xo9MjMzAQAWFhZ46KGHYGNj02j56dOnIzIy
/// EiEhIa3VBGqiixcvoqSkBO7u7nBwcJC7OUTtoqamBhkZGcjLy8MDDzyAwMBAdO/e
/// Xe5m3VGrzaArKiowcOBAPPPMMxgwYADs7e0RFRWF69evN1g+NTUVxcXFrVV9iwwZ
/// MgQHDx6UtQ3t6fDhw+jduzecnZ0xcOBA7N69W+4mEbWbkSNHIjw8HCtXrsTrr78O
/// d3d3fPvtt3I3645afYnjiy++QFVVFdLS0pCdnY3IyMgGy2VkZCA2Nra1q2+WEydO
/// 4MaNG7K2oT3Z29sjMTERp0+flrspRO3u448/RmlpKbKyspCXl4fJkyfjv/7rv6DX
/// 6+VuWqPaZA3a3Nwcvr6+WLFiBQ4ePIijR49K+2bPng2tVgutVov9+/c3ePyqVavw
/// 2WefISkpCUOHDkVAQADWr18v7c/JyUF8fDwCAgLwwgsv4OeffzY6R2ZmJl599VUE
/// BgYiJCQE//M//yPti4qKglarRU1NDVasWCG1p6ioyOAc1dXV+Omnn5CdnX2vQ6II
/// jz/+OF5++WX07dtX7qYQtbtHHnkEarUawO23XQ8bNgzl5eUoLS2VuWWNa9ObhEOH
/// DoVKpcIvv/wibQsLC4NGo8HBgweRl5fX4HFHjhzBv/71L7zzzjsYN24cJk6cKJU9
/// f/48AgMDIYTA4sWLMWTIEIwaNQrp6enS8ceOHcNTTz2Furo6zJ8/H5MmTcKuXbuk
/// /S+++CI0Gg3MzMzw9NNPQ6PRQKPRoGvXrgbtuHz5MoYPH44PPvigNYeFiGSk1+tx
/// 7tw5rF69Gk899RQcHR3lblKj2vTDkiwsLGBnZ4fLly9L20aMGAEAePPNN+94bGFh
/// IXJzc41Cc8WKFXjiiSewfv16qFQqhIWFSYO9ZcsWAMCSJUswZMgQfP7559JxUVFR
/// 0vcajQYAMHHiRDz99NMYPXp0g23o3Lkz/Pz84Obm1oxeE5FS7dixQ/r37uvrix9/
/// /FExHyLVkDb/NDudTiddVjTH0KFDjcIZuL10oVarkZCQIG07f/48rl69Kr3OysrC
/// 7NmzDY5ryQ/ByckJv/76a7OPIyJlCg0NRW5uLi5evIiEhARERkbi559/blFGtYc2
/// DeiKigpUVFTAxcWl2cf26NGj0XN6enrC3t5e2jZs2DDY2dlJr//44w9YW1s3v8FE
/// dF+ztraGh4cHPDw8sHnzZri5ueHAgQMIDQ2Vu2kNatOATkpKgkqlalHnG5vxenl5
/// wcnJCfPmzWv02D59+iArK+uudZiZmUGn0zW6v66uDuXl5bCwsGDgE91nrKysANye
/// 0ClVq98kvHz5Mo4dO4aPP/4Yc+bMwSuvvNKqTw3ExcVhw4YNSE5OlrYdP34cO3fu
/// lF6//PLL+Pe//42ffvoJwO1llo0bNxqdy9PTEz/88AOqqqoarKugoAAODg6YNWtW
/// q7VfTn/++Sfy8vKkG65Xr15FXl5eh3rUkDqmyspKrFy5Evn5+airq8OlS5fw+uuv
/// o2vXrggICJC7eY0TraSsrEwAEACElZWV8Pb2Fu+9957Q6XRSmY0bN0pl/vrl6upq
/// cK4xY8aI1157rdG61qxZIx544AFhZ2cnbGxshIODg/jkk0+k/XV1dWL+/PnC2tpa
/// dOvWTVhYWIigoCCj86SkpIjHH39cdO7cWQAQv//+u8H+/Px8AUBMnjy5pcNioL6/
/// csnOzm5w/JcuXdou9cvdf7nrl5vc/Zez/j/++EM8+uijAoBQqVQCgPDw8BDJycnt
/// 1oaW9F/1/weaHCEE8vPzoVKp4OrqCjMz49UavV6PvLw82NjYoFevXjK00lD9so2J
/// Dvk9k7v/ctcvN7n7L3f9AHD9+nWUlJTAzs4Ozs7O7Vp3S/pvsgFtipTwCyonufsv
/// d/1yk7v/ctcvt5b0n59mR0SkUAxoIiKFYkATESkUA5qISKEY0ERECsWAJiJSKAY0
/// EZFCMaCJiBSKAU1EpFBt/nnQZEzJHxDeEXD85cXxbzrOoImIFIqfxUFEpFCcQRMR
/// KRQDmohIoRjQHYgQosN+1KMScPzlZYrjz4DuQI4ePYq0tDS5m9FhcfzlZYrjz8fs
/// OpBt27ZBpVIp+2+w3cc4/vIyxfHnUxwdhBACDz30EOrq6lBQUMBnUdsZx19epjr+
/// XOLoINLS0lBQUICioiKTu8y7H3D85WWq48+A7iC++eYb6ftt27bJ2JKOieMvL1Md
/// fy5xdAD1l3cFBQUAABcXF5O6zDN1HH95mfL4cwbdAdRf3tUztcs8U8fxl5cpjz8D
/// ugP46+VdPVO6zDN1HH95mfL4c4njPieEgLu7O/7zn/8YbHd1dcV//vMfk7jMM2Uc
/// f3mZ+vhzBn2fO3r0qNEvJwAUFhaazGWeKeP4y8vUx58BfZ+706WcqVzmmTKOv7xM
/// ffy5xHEfa+zyrp6pXOaZKo6/vO6H8ecM+j7W2OVdPVO5zDNVHH953Q/jz4C+jzXl
/// Es4ULvNMFcdfXvfD+HOJ4z51t8u7eqZwmWeKOP7yul/GnzPo+1RaWtpdfzkB07jM
/// M0Ucf3ndL+PPGTQRkUJxBk1EpFAM6A4kKCgIQUFBcjejw+L4y8sUx59LHB1I/Y0Q
/// /sjlwfGXlymOP2fQREQKxYAmIlIoBjQRkUIxoImIFIoBTUSkUAxoIiKFYkATESkU
/// A5qISKEY0ERECsWAJiJSKAY0EZFCMaCJiBSKAU1EpFAMaCIihWJAExEplJncDaD2
/// M3jwYLmb0KFx/OVliuPPD+wnIlIoLnEQESkUA5qISKEY0ERECsWAJiJSKAY0EZFC
/// 8TG7dlT/Z987OrkeHOL438bxl1dzxp8zaCIiheIMWgYd9dFzpcygOP7y4vg3HWfQ
/// REQKxYAmIlIoBjQRkUIxoImIFIoBTUSkUAxoIiKFYkATESlUi56DzsvLQ1lZGXx8
/// fGBmdudTLFu2DC4uLoiNjW1RA+UihEBGRgbOnj0LOzs7BAYGws7OTu5mEVEH0qIZ
/// dEREBAYOHIgDBw7ctezhw4fx22+/taSaO9qxYwciIiJa/bz1BgwYgMDAQCxZsgTx
/// 8fF4+OGHsW/fvjarj4jo75od0OfOncOZM2cwbNgwbN++vS3a1CTXrl3DyZMn2+z8
/// r776Kq5cuYLTp0/jwoULCA0NxUsvvdRm9RER/V2zA3r79u3w9fXFhAkTGgzoEydO
/// YMyYMRg4cCCWL19u9LbOH3/8EdHR0fD390dAQAASEhJQUVEh7d+9ezdmz56Nzz77
/// DE8++SQiIiKwc+dOaX9ycjK0Wi3Wrl2L0tJSaLVaaLVaJCYmGtSTmpqKmJgYDBo0
/// COPHj0d2drZRW6OionD8+HHMnz8fgwYNQlhYGDIyMgAA06dPl5Y0zMzMMHbsWFy8
/// eBFXrlxp7pAREbVIiwI6LCwMI0aMQEFBAbKysqR9JSUlGDJkCHr16oUlS5YgLS3N
/// aBlk79696NevHxITE5GQkIC9e/ciLi5O2n/27Fl89NFH+Oqrr7BgwQIMGDAAY8aM
/// walTpwAAnp6e0Gg08Pf3h7W1NTQaDTQaDZ555hnpHCkpKQgNDYW7uzuWLl0Kd3d3
/// BAQEoKSkxKAt3377LSZPnoz8/HxMnz4dQ4YMwblz5xrsd1ZWFnr16oVu3bo1d8iI
/// iFpGNMPVq1eFWq0WBw8eFEII4ePjIxITE6X9ixYtEl5eXqKurk4IIcQff/whbG1t
/// xZw5cxo95759+4RarRZ6vV4IIcSaNWuEWq0WhYWFUpng4GAxefJkg+M+//xz4ebm
/// 1uA5g4KCxKuvvmqwLTg4WCxcuNBgW6dOnYRWq71Lr4U4c+aMsLa2Fl9//fVdy94J
/// ANHMIb+vyN1/ueuXm9z9l7t+ubWk/816imP37t2wsbFBYGAgACAsLAzff/895s+f
/// DwDIzs6Gn5+f9KlNXbp0wRNPPGFwjsLCQqxatQoZGRmorq5GdXU19Ho9ysvLYW9v
/// DwDo1asXXFxcpGP8/f2RlpbW5HZmZmbC1tYWb775prStvLwcOTk5RmVHjx59x3Nd
/// v34dY8aMQUxMDMaNG9fkNhAR3atmBXT9mvOzzz4L4PaSxunTp1FUVAQXFxdUVVWh
/// e/fuBsdYWlpK39+6dQshISEYMGAAli1bhl69euHkyZOIjIyETqdr8BgAsLCwQGVl
/// ZZPaqNPpUF1dDUdHRynwgdvrzR4eHkblHR0dGz1XZWUlnnvuOfTp0wcfffRRk+on
/// ImotTQ7ompoaJCcnY9KkSQgICJC2x8fHY8eOHZg6dSp69+4trRUDt58lzs3NhZ+f
/// H4DbM+zz588jPT1dCs9ffvnFqK6LFy+ipqZGCur8/Hy4ubkZlDE3NzcIdalDZmbw
/// 8PCAj48PZs6c2dTuGamtrcWYMWNgbW2NLVu2QK1Wt/hcREQt0eSbhCkpKaisrMTs
/// 2bOlG3MajQahoaHSzDoqKgqHDh3C4cOHAQAbN25EQUGBdA4HBweoVCppf2FhIZYv
/// X25UV1VVFVavXg0AOH36NLZv3w6NRmNQxsPDA5cvX0Zqairq6uoM9sXFxWHlypU4
/// ceIEAECv12P//v1ITU1tancRHR2N/Px8rF69GsXFxcjLy0NeXh5qa2ubfA4ionvS
/// 1MXqKVOmCG9vb6Pt69atExYWFuLmzZtCCCEWLlwo1Gq16Natm/Dx8RGBgYEGNwkT
/// ExOFubm5cHJyEg4ODuLdd98VAMSVK1eEELdvEvbp00cEBwcLe3t7oVarxeTJk4VO
/// pzOqe8aMGcLR0VEAECEhIdJ2nU4nZs2aJSwtLUWPHj2EhYWFcHZ2Fj/88IPB8Z06
/// dRJ79uwxOq9er5cW9P/+lZGR0dQhMwLeJOFNKhnJ3X+565dbS/qv+v8DW1VFRQWK
/// i4vh5eWFTp2MJ+nXr19HSUkJPDw8YGVlZbDv/fffx2effYaTJ0/i7Nmz6NGjh8Fa
/// cnPodDrk5ubCxsYGTk5Osv/Jn/r622DITYLc/Ze7frnJ3X+565dbS/rfJn+T0NbW
/// Fo888kij+x0cHODg4HDX83h5ed1TO8zMzNC3b997OgcRkVwU92l2lpaW6Nq1q9zN
/// ICKSXZsscVDDeInHS2w5yd1/ueuXW0v6r7gZNBER3caAJiJSKAY0EZFCMaCJiBSK
/// AU1EZeKaowAAElJJREFUpFAMaCIihWJAExEpVJu8k5DuTO63nHd0HH95cfybjjNo
/// IiKF4jsJiYgUijNoIiKFYkATESkUA5qISKEY0ERECsWAJiJSKAZ0BxIUFISgoCC5
/// m9FhcfzlZYrjz8fsOpCO/oHpcuP4y8sUx58zaCIihWJAExEpFAOaiEihGNBERArF
/// gCYiUigGNBGRQjGgiYgUigFNRKRQDGgiIoViQBMRKRQDmohIoRjQREQKxYAmIlIo
/// BjQRkUIxoImIFMpM7gZQ+xk8eLDcTejQOP7yMsXx5wf2ExEpFJc4iIgUigFNRKRQ
/// DGgiIoViQBMRKRQDmohIofiYXTuq/7PvHZ1cDw5x/G/j+MurOePPGTQRkUJxBi2D
/// jvrouVJmUBx/eXH8m44zaCIihWJAExEpFAOaiEihGNBERArFgCYiUigGNBGRQjGg
/// iYgUqkXPQefl5aGsrAw+Pj4wM7vzKZYtWwYXFxfExsa2qIFyKyoqwuXLl+Hp6Qk7
/// Ozu5m0MmLjMzEzk5OejatSsCAgLg4OAgd5NIwVo0g46IiMDAgQNx4MCBu5Y9fPgw
/// fvvtt5ZUc0c7duxAREREq5+33p49e+Dq6gpXV9cm95XoTgYPHgx/f38sXrwYU6ZM
/// gaenJ3bu3Cl3s0jBmh3Q586dw5kzZzBs2DBs3769LdrUJNeuXcPJkyfb7PyOjo54
/// 9913kZGR0WZ1UMcSHR2NS5cuITs7GxcuXEBkZCReeukl6HQ6uZtGCtXsgN6+fTt8
/// fX0xYcKEBgP6xIkTGDNmDAYOHIjly5cbva3zxx9/RHR0NPz9/REQEICEhARUVFRI
/// +3fv3o3Zs2fjs88+w5NPPomIiAiDWUZycjK0Wi3Wrl2L0tJSaLVaaLVaJCYmGtST
/// mpqKmJgYDBo0COPHj0d2drZRW6OionD8+HHMnz8fgwYNQlhYmBTI/fv3R2xsLDw9
/// PZs7REQN+u///m9069YNANCpUye8+OKLKCsrQ0FBgcwtI6VqUUCHhYVhxIgRKCgo
/// QFZWlrSvpKQEQ4YMQa9evbBkyRKkpaUZLQ3s3bsX/fr1Q2JiIhISErB3717ExcVJ
/// +8+ePYuPPvoIX331FRYsWIABAwZgzJgxOHXqFADA09MTGo0G/v7+sLa2hkajgUaj
/// wTPPPCOdIyUlBaGhoXB3d8fSpUvh7u6OgIAAlJSUGLTl22+/xeTJk5Gfn4/p06dj
/// yJAhOHfuXHOHhKhFsrKyYG9vD2dnZ7mbQkolmuHq1atCrVaLgwcPCiGE8PHxEYmJ
/// idL+RYsWCS8vL1FXVyeEEOKPP/4Qtra2Ys6cOY2ec9++fUKtVgu9Xi+EEGLNmjVC
/// rVaLwsJCqUxwcLCYPHmywXGff/65cHNza/CcQUFB4tVXXzXYFhwcLBYuXGiwrVOn
/// TkKr1d6xz+Xl5QKASEpKumO5pgAgmjnk9xW5+y93/X9VWFgo7O3txaefftpudcrd
/// f7nrl1tL+t+spzh2794NGxsbBAYGAgDCwsLw/fffY/78+QCA7Oxs+Pn5SZ/a1KVL
/// FzzxxBMG5ygsLMSqVauQkZGB6upqVFdXQ6/Xo7y8HPb29gCAXr16wcXFRTrG398f
/// aWlpTW5nZmYmbG1t8eabb0rbysvLkZOTY1R29OjRTT4vUWuoqKjA888/j5EjR2Li
/// xIlyN4cUrFkBXb/m/OyzzwK4vaRx+vRpFBUVwcXFBVVVVejevbvBMZaWltL3t27d
/// QkhICAYMGIBly5ahV69eOHnyJCIjIw1ulPz1GACwsLBAZWVlk9qo0+lQXV0NR0dH
/// KfCB2+vNHh4eRuUdHR2bdF6i1lBbW4vIyEh0794dGzZsUMxHgJIyNTmga2pqkJyc
/// jEmTJiEgIEDaHh8fjx07dmDq1Kno3bu3tFYM3P7c19zcXPj5+QG4PcM+f/480tPT
/// pfD85ZdfjOq6ePEiampqpKDOz8+Hm5ubQRlzc/MG736bmZnBw8MDPj4+mDlzZlO7
/// R9Tm9Ho9YmNjUVlZib1796Jz585yN4kUrsk3CVNSUlBZWYnZs2dLN+Y0Gg1CQ0Ol
/// mXVUVBQOHTqEw4cPAwA2btxocIfawcEBKpVK2l9YWIjly5cb1VVVVYXVq1cDAE6f
/// Po3t27dDo9EYlPHw8MDly5eRmpqKuro6g31xcXFYuXIlTpw4AeD2P4z9+/cjNTW1
/// qd1FbW0t8vLycOHCBQDA5cuXkZeXh/Ly8iafg+ivJk6ciPT0dKxduxZXrlxBXl4e
/// 8vLyUFNTI3fTSKmaulg9ZcoU4e3tbbR93bp1wsLCQty8eVMIIcTChQuFWq0W3bp1
/// Ez4+PiIwMNDgJmFiYqIwNzcXTk5OwsHBQbz77rsCgLhy5YoQ4vZNwj59+ojg4GBh
/// b28v1Gq1mDx5stDpdEZ1z5gxQzg6OgoAIiQkRNqu0+nErFmzhKWlpejRo4ewsLAQ
/// zs7O4ocffjA4vlOnTmLPnj0N9vfYsWPSov5fvz744IOmDpkR8CZJh75JZW1t3eDv
/// VP1N97Ymd//lrl9uLem/6v8PbFUVFRUoLi6Gl5cXOnUynqRfv34dJSUl8PDwgJWV
/// lcG+999/H5999hlOnjyJs2fPokePHgZryc2h0+mQm5sLGxsbODk5yb7eV19/Gwy5
/// SZC7/3LXLze5+y93/XJrSf/b5G8S2tra4pFHHml0v4ODQ5M+g8DLy+ue2mFmZoa+
/// ffve0zmIiOSiuE+zs7S0RNeuXeVuBhGR7NpkiYMaxks8XmLLSe7+y12/3FrSf8XN
/// oImI6DYGNBGRQjGgiYgUigFNRKRQDGgiIoViQBMRKRQDmohIodrknYR0Z3K/5byj
/// 4/jLi+PfdJxBExEpFN9JSESkUJxBExEpFAOaiEihGNBERArFgCYiUigGNBGRQjGg
/// iYgUigFNRKRQfCehCbl69SoKCgqMtnfv3h29e/dut3aMHz8eb775Jnx8fNqtzvaU
/// l5eHsrIy+Pj4wMysbf6J6HQ6REdHIzEx8Y5/v5Nu0+v1yMzMBABYWFjgoYcego2N
/// jcytaget8vfEqV189NFHAoCwt7c3+Jo5c2a7tsPc3Fz8+OOP7Vpne3r00UcFALF3
/// 794WHf/bb78JPz8/UV1d3WiZ2tpaYW9vL44cOdLSZnYoZWVlAoDo0qWLMDMzE2Zm
/// ZkKr1Ypr167J3bQ2xSUOE2Nubo7r168bfK1Zs0buZt03zp8/jzNnziA0NBTbt29v
/// 0TkqKytx/Phx1NXVNVqmc+fOuH79OgICAlra1A7piy++QFVVFdLS0pCdnY3IyEi5
/// m9SmGND3mbKyMmi1Wpw5cwYzZszAwIEDMXr0aOTm5kpl/v3vf+P5559HQEAAZs6c
/// ifLycoNzHDt2DC+++CJ8fX0RHByMd955x6iea9euYeLEifDz88OkSZNw8+bNNu9b
/// e/j+++/h6+uL2NjYRgN627Zt0Gq1GDhwIF544QX89NNPAIBTp05Bq9XirbfeAgDE
/// xsZCq9Vi8uTJBsePHz8eWq0WWq0WOTk5Bvu2bt2Kf/zjHwbbdDodJkyYgPT0dGlb
/// amoqYmJiMGjQIIwfPx7Z2dn33HdTYW5uDl9fX6xYsQIHDx7E0aNHpX05OTl45ZVX
/// 8OSTT2Ls2LHYtWuXwbFz5sxBUlIS5s6dCz8/P2i1WhQVFRmUycnJQXx8PAICAvDC
/// Cy/g559/bpd+NYQBbYLKysoMvvR6vbSvuroa27Ztw4QJE/Dnn39i5syZ8Pb2xoUL
/// FwAAixcvxrx58xAREYFFixYhNzcXzz77rPSXhsvKyjB8+HB4eHjggw8+wOuvv46L
/// Fy8atWHhwoUYNGgQ5s2bh127dmHJkiXt0ve2tn37doSFhWHEiBEoKChAVlaWwf73
/// 338fL730Evr3749ly5Zh+PDhUpA7OjpCo9EgNDQUABAZGQmNRoPnnnvO4Bxjx45F
/// ZGQktm3bhtLSUoN9vXv3xooVK3D58mVp2/79+/Hdd99Ja9UpKSkIDQ2Fu7s7li5d
/// Cnd3dwQEBKCkpKTVx0PJhg4dCpVKhV9++QXA7SuXkJAQlJeXY/HixXj88cfxwgsv
/// GAT4nj178Nprr8HOzg4LFy7E2bNnMXXqVGn/+fPnERgYCCEEFi9ejCFDhmDUqFEG
/// /zm2K7nXWKjp6teg//518uRJqUxxcbEAIGbNmmV0fHl5ubC0tBRff/21tO3mzZvC
/// yspKHDp0SAghRHp6ugAgrly50mg7zM3NxTvvvCO9TkxMFIMGDWqNLsrq6tWrQq1W
/// i4MHDwohhPDx8RGJiYnS/lu3bomuXbuKlStXGhxXV1dn8PrIkSMCgKisrGy0rtra
/// WgFAGve/nuvhhx8WH374obQtLi5OaDQa6XVQUJB49dVXDY4LDg4WCxcubFpHTVD9
/// GvS3335rsN3e3l7MnTtXCCHEJ598Iuzs7ERVVZW0PyIiwmDs+vXrJyZMmCC9/uab
/// b0TXrl2l1/Hx8WLw4MEGP9MpU6aIqKioVu9TU/ApDhNjZmaGM2fOGGxzcXExKjd6
/// 9GijbdnZ2aipqcGhQ4ekO+IAYGVlhZycHAwePBiPPvooXF1dERgYiLFjxyI0NBTB
/// wcHo3Lmzwbm8vb2l73v16mU0EzRFu3fvho2NDQIDAwEAYWFh+P777zF//nwAQH5+
/// Pm7evIlRo0YZHNean2+sUqkQHR2NLVu2YNq0aaitrUVSUhK++OILqUxmZiZsbW3x
/// 5ptvStvKy8uNlks6Ap1OB7VaDeD20oS3tzesrKyk/U8++SS2bNlicMxff3d79uyJ
/// mzdv4tatW+jcuTMyMzOhVquRkJAglTl//jyuXr3axj1pGAPaxKhUKnh4eNy1nKOj
/// o9G2P/74AwDg5ORk8PjY3LlzpUfmbGxskJGRgU2bNiE5ORmrV69G//79cfjwYVhY
/// WEjH/D2wxX3wqbX1SxXPPvssAKCkpASnT59GUVERXFxcUFlZCQCwtrZu03ZER0dj
/// yZIlKCgoQEZGBtRqtdQmnU6H6upqODo6wt7eXjomKiqqSb8X95OKigpUVFRIE5TK
/// ykpYWloalLGyskJVVZXBtr/+7tb/51r/+1tRUQFPT0+DsR02bBjs7OzapA93w4Du
/// QPr06QMAeP755/HEE080Wq579+6YMWMGZsyYgbNnz+KRRx7BkSNHEBwc3E4tbX81
/// NTVITk7GpEmTDJ6siI+Px44dOzB16lR4enpCpVIhKysLDz30UKPnqv/PT6fTtagt
/// ffv2hZ+fH7Zu3Ypff/0VL774ohQqZmZm8PDwgI+PD2bOnNmi898vkpKSoFKppDV/
/// Nzc37N+/36DM+fPn4ebm1uRzenl5wcnJCfPmzWvVtrYUbxJ2IG5ubggJCcGMGTOk
/// S7aqqip8+eWXuHTpEgDg3Llz2LdvnzSjqL9Z5eTkJE+j20lKSgoqKysxe/ZsaDQa
/// 6euvj9t17doVkZGReOutt5Cfnw/g9tLCd999Z3Cuhx56CGq1Gt9//32LQzomJgYb
/// NmzAzp07ERMTY7AvLi4OK1euxIkTJwDcfhPH/v37kZqa2qK6TMnly5dx7NgxfPzx
/// x5gzZw5eeeUV9O3bFwCg0WiQn5+Pr776CsDtJb2tW7di3LhxTT5/XFwcNmzYgOTk
/// ZGnb8ePHsXPnztbtSFPJsvJNLfLRRx8Jc3PzO5apv0l4+vTpBvdfunRJjBw5UpiZ
/// mYmePXuKTp06CR8fH3Hx4kUhxO2bhD169BBWVlbCxcVFdOnSRSxfvtzgHH9/o8r6
/// 9euFu7v7PfZOXlOmTBHe3t5G29etWycsLCzEzZs3hRBCXL9+XURGRgq1Wi0efPBB
/// YW5uLhYsWGB03Jo1a4SLi4tQqVTCyclJ2v722283eKN3+PDhBsdfvHhRqNVq4ebm
/// JvR6vcE+nU4nZs2aJSwtLUWPHj2EhYWFcHZ2Fj/88ENrDIUi1d8kBCCsrKyEt7e3
/// eO+994ROpzMo98EHHwgrKyvRrVs3oVarRXR0tKitrZX29+vXT7z//vvS60OHDgkA
/// oqamRtq2Zs0a8cADDwg7OzthY2MjHBwcxCeffNL2nWwA/+RVB1VVVYULFy7gwQcf
/// RLdu3Qz2CSFQVFSEmzdvwt3dvc3XXE1RTU0N8vPz4eTkhAceeECWNuh0OuTm5sLG
/// xgZOTk78Y6z/788//5R+Ni19O7gQAvn5+VCpVHB1dW2zt/zfDQOaiEihuAZNRKRQ
/// DGgiIoViQBMRKRQDmohIoRjQREQKxYAmIlIoBjQRkUIxoImIFIoBTUSkUAxoIiKF
/// YkATESkUA5qISKEY0ERECsWAJiJSKAY0EZFCMaCJiBSKAU1EpFAMaCIihfo/298P
/// fnyMJowAAAAASUVORK5CYII=
/// ">
/// </div>
///
/// Columns depict method call chains. The __Direct__ row is the final call destination for
/// all stream variants. At the bottom of each column is the expected state before
/// the call to a method. Numbers in call site boxes are the points of state transitions.
///
/// `SearchStream` has two variants, `Direct` and `Adapted`, encoded by the type system.
/// The `Direct` version is the regular one; `Adapted` passes each method call through a
/// chain of adapters before executing the direct call. In the diagram, `Direct` calls
/// start from the top of the column, while `Adapted` calls start at the bottom.
///
/// Every `SearchStream` is created in the `Fresh` state, and the `start()` method is automatically
/// called. In the `Direct` variant, `start()` is not publicly visible; in `Adapted` it has to be
/// for adapter chaining to work. The direct version of `start()` will change state from `Fresh`
/// to `Active` at point (1), when the protocol request is successfully written to the network
/// socket. Any error in submitting the request will change the state to `Error`. Calling
/// `start()` in any state but `Fresh` will just return the stream handle.
///
/// Iterating through the stream with `next()` requires the `Active` state, which turns into `Done`
/// when the final Search message is received. However, the transition must not be made in the
/// direct method, since the adapters may need to keep providing additional entries even when
/// the original operation is over. Therefore, point (2) occurs at the end of the first call
/// in the chain (for `Adapted`), or in the shim method (for `Direct`). As before, any error will
/// result in the `Error` state.
///
/// The `finish()` method may be called at any time. Adapters along the way can behave differently
/// according to state, and the final direct call will change the state to `Closed` at (3). Calling
/// `finish()` on a stream in the `Closed` state will return a synthetic error-bearing `LdapResult`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamState {
    /// Stream which hasn't yet been initialized in `start()`.
    Fresh,
    /// Initialized stream which can be iterated through with `next()`.
    Active,
    /// Stream from which all entries have been retrieved.
    Done,
    /// Properly finalized stream on which `finish()` was called.
    Closed,
    /// Stream in an error state after some fallible operation.
    Error,
}

/// Asynchronous handle for obtaining a stream of search results. __*__
///
/// A streaming search should be used for situations where the expected
/// size of result entries varies considerably between searches, and/or
/// can rise above a few tens to hundreds of KB. This is more of a concern
/// for a long-lived process which is expected to have a predictable memory
/// footprint (i.e., a server), but can also help with one-off searches if
/// the result set is in the tens of thounsands of entries.
///
/// Once initiated, a streaming search is driven to the end by repeatedly calling
/// [`next()`](#method.next) until it returns `Ok(None)` or an error. Then, a call
/// to [`finish()`](#method.finish) will return the overall result of the search.
/// Calling `finish()` earlier will terminate search result processing in the
/// client; it is the user's responsibility to inform the server that the operation
/// has been terminated by sending an Abandon or a Cancel operation.
///
/// There are two variants of `SearchStream`, `Direct` and `Adapted`. The former calls
/// stream operations directly, while the latter first passes through a chain of
/// [adapters](adapters/index.html) given at the time of stream creation. Both variants
/// are used in the same manner.
#[derive(Debug)]
pub struct SearchStream<S, Mode = Direct> {
    pub(crate) ldap: Ldap,
    pub(crate) rx: Option<mpsc::UnboundedReceiver<(SearchItem, Vec<Control>)>>,
    state: StreamState,
    adapters: Vec<Arc<Mutex<Box<dyn Adapter<S>>>>>,
    ax: usize,
    timeout: Option<Duration>,
    pub res: Option<LdapResult>,
    mode: PhantomData<Mode>,
}

impl<S> Into<SearchStream<S, Direct>> for SearchStream<S, Adapted> {
    fn into(self) -> SearchStream<S, Direct> {
        unsafe { std::mem::transmute::<_, SearchStream<S, Direct>>(self) }
    }
}

impl<S> Into<SearchStream<S, Adapted>> for SearchStream<S, Direct> {
    fn into(self) -> SearchStream<S, Adapted> {
        unsafe { std::mem::transmute::<_, SearchStream<S, Adapted>>(self) }
    }
}

impl<'a, S> Into<&'a mut SearchStream<S, Direct>> for &'a mut SearchStream<S, Adapted> {
    #[allow(clippy::transmute_ptr_to_ptr)]
    fn into(self) -> &'a mut SearchStream<S, Direct> {
        unsafe { std::mem::transmute::<_, &'a mut SearchStream<S, Direct>>(self) }
    }
}

impl<S> SearchStream<S, Direct>
where
    S: AsRef<str> + Send + Sync + 'static,
{
    pub(crate) fn new(ldap: Ldap) -> Self {
        SearchStream {
            ldap,
            rx: None,
            state: StreamState::Fresh,
            adapters: vec![],
            ax: 0,
            timeout: None,
            res: None,
            mode: PhantomData,
        }
    }

    pub(crate) async fn start(
        mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<Self> {
        let opts = match self.ldap.search_opts.take() {
            Some(opts) => opts,
            None => SearchOptions::new(),
        };
        self.timeout = self.ldap.timeout;
        let req = Tag::Sequence(Sequence {
            id: 3,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(base.as_bytes()),
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: scope as i64,
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: opts.deref as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: opts.sizelimit as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: opts.timelimit as i64,
                    ..Default::default()
                }),
                Tag::Boolean(Boolean {
                    inner: opts.typesonly,
                    ..Default::default()
                }),
                match parse_filter(filter) {
                    Ok(filter) => filter,
                    _ => {
                        self.state = StreamState::Error;
                        return Err(LdapError::FilterParsing);
                    }
                },
                Tag::Sequence(Sequence {
                    inner: attrs
                        .into_iter()
                        .map(|s| {
                            Tag::OctetString(OctetString {
                                inner: Vec::from(s.as_ref()),
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        let (tx, rx) = mpsc::unbounded_channel();
        self.rx = Some(rx);
        if let Some(timeout) = self.timeout {
            self.ldap.with_timeout(timeout);
        }
        match self.ldap.op_call(LdapOp::Search(tx), req).await {
            Err(e) => {
                self.state = StreamState::Error;
                Err(e)
            }
            _ => {
                self.state = StreamState::Active;
                Ok(self)
            }
        }
    }

    /// Fetch the next item from the result stream.
    ///
    /// Returns `Ok(None)` at the end of the stream.
    #[allow(clippy::should_implement_trait)]
    pub async fn next(&mut self) -> Result<Option<ResultEntry>> {
        if self.state != StreamState::Active {
            return Ok(None);
        }
        let res = self.inner_next().await;
        match res {
            Ok(None) => self.state = StreamState::Done,
            Err(_) => self.state = StreamState::Error,
            _ => (),
        }
        res
    }

    pub(crate) async fn inner_next(&mut self) -> Result<Option<ResultEntry>> {
        let item = if let Some(timeout) = self.ldap.timeout {
            let res = time::timeout(timeout, self.rx.as_mut().unwrap().recv()).await;
            if res.is_err() {
                let last_id = self.ldap.last_id;
                self.ldap.id_scrub_tx.send(last_id)?;
            }
            res?
        } else {
            self.rx.as_mut().unwrap().recv().await
        };
        let (item, controls) = match item {
            Some((item, controls)) => (item, controls),
            None => {
                self.rx = None;
                return Err(LdapError::EndOfStream);
            }
        };
        match item {
            SearchItem::Entry(tag) | SearchItem::Referral(tag) => {
                return Ok(Some(ResultEntry(tag, controls)))
            }
            SearchItem::Done(mut res) => {
                res.ctrls = controls;
                self.res = Some(res);
                self.rx = None;
            }
        }
        Ok(None)
    }

    /// Return the overall result of the Search.
    ///
    /// This method can be called at any time. If the stream has been read to the
    /// end, the return value will be the actual result returned by the server.
    /// Otherwise, a synthetic cancellation result is returned, and it's the user's
    /// responsibility to abandon or cancel the operation on the server.
    pub async fn finish(&mut self) -> LdapResult {
        if self.state == StreamState::Closed {
            return LdapResult {
                rc: 80,
                matched: String::from(""),
                text: String::from("stream already finalized"),
                refs: vec![],
                ctrls: vec![],
            };
        }
        if self.state != StreamState::Done {
            let last_id = self.ldap.last_id;
            if let Err(e) = self.ldap.id_scrub_tx.send(last_id) {
                warn!(
                    "error sending scrub message from SearchStream::finish() for ID {}: {}",
                    last_id, e
                );
            }
        }
        self.state = StreamState::Closed;
        self.rx = None;
        self.res.take().unwrap_or_else(|| LdapResult {
            rc: 88,
            matched: String::from(""),
            text: String::from("user cancelled"),
            refs: vec![],
            ctrls: vec![],
        })
    }
}

impl<S> SearchStream<S, Adapted>
where
    S: AsRef<str> + Send + Sync + 'static,
{
    pub(crate) fn new(ldap: Ldap, adapters: Vec<Box<dyn Adapter<S>>>) -> Self {
        SearchStream {
            ldap,
            rx: None,
            state: StreamState::Fresh,
            adapters: adapters.into_iter().map(Mutex::new).map(Arc::new).collect(),
            ax: 0,
            timeout: None,
            res: None,
            mode: PhantomData,
        }
    }

    /// Initialize a streaming Search.
    ///
    /// This method exists as an initialization point for search adapters, and is
    /// not meant for calling from regular user code. It must be public for user-defined
    /// adapters to work, but explicitly calling it on a `SearchStream<_, Adapted>` handle
    /// is a no-op: it will return an `Ok`-wrapped handle on which it was called.
    pub async fn start(
        self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<Self> {
        let mut self_ = self;
        if self_.state != StreamState::Fresh {
            return Ok(self_);
        }
        if self_.ax == self_.adapters.len() {
            self_.ax = 0;
            let stream: SearchStream<S, Direct> = self_.into();
            let res = stream.start(base, scope, filter, attrs).await.map(|s| {
                let stream: SearchStream<S, Adapted> = s.into();
                stream
            });
            return res;
        }
        let adapter = self_.adapters[self_.ax].clone();
        let mut adapter = adapter.lock().await;
        self_.ax += 1;
        (&mut adapter)
            .start(self_, base, scope, filter, attrs)
            .await
    }

    /// Fetch the next item from the result stream after executing the adapter chain.
    ///
    /// Returns `Ok(None)` at the end of the stream.
    #[allow(clippy::should_implement_trait)]
    pub async fn next(&mut self) -> Result<Option<ResultEntry>> {
        if self.state != StreamState::Active {
            return Ok(None);
        }
        if self.ax == self.adapters.len() {
            let stream: &mut SearchStream<S, Direct> = self.into();
            let res = stream.inner_next().await;
            if res.is_err() {
                self.state = StreamState::Error;
            }
            return res;
        }
        let adapter = self.adapters[self.ax].clone();
        let mut adapter = adapter.lock().await;
        self.ax += 1;
        let res = (&mut adapter).next(self).await;
        self.ax -= 1;
        match res {
            Ok(None) if self.ax == 0 => self.state = StreamState::Done,
            Err(_) => self.state = StreamState::Error,
            _ => (),
        }
        res
    }

    /// Return the overall result of the Search, executing the `finish()` method of
    /// all adapters in the chain.
    pub async fn finish(&mut self) -> LdapResult {
        if self.state == StreamState::Closed {
            return LdapResult {
                rc: 80,
                matched: String::from(""),
                text: String::from("stream already finalized"),
                refs: vec![],
                ctrls: vec![],
            };
        }
        if self.ax == self.adapters.len() {
            let stream: &mut SearchStream<S, Direct> = self.into();
            return stream.finish().await;
        }
        let adapter = self.adapters[self.ax].clone();
        let mut adapter = adapter.lock().await;
        self.ax += 1;
        let res = (&mut adapter).finish(self).await;
        self.ax -= 1;
        res
    }

    /// Return a vector of the remaining adapters in the chain at the point
    /// of the method call. Adapter instances are cloned and collected into the
    /// resulting vector. The purpose of this method is to enable uniformly
    /// configured Search calls on the connections newly opened in an adapter.
    pub async fn adapter_chain_tail(&mut self) -> Vec<Box<dyn Adapter<S>>> {
        let mut chain = vec![];
        for ix in self.ax..self.adapters.len() {
            let adapter = self.adapters[ix].clone();
            let adapter = adapter.lock().await;
            chain.push(adapter.as_ref().box_clone());
        }
        chain
    }
}

impl<S, T> SearchStream<S, T>
where
    S: AsRef<str> + Send + Sync + 'static,
{
    /// Return the `Ldap` handle of the stream.
    pub fn ldap_handle(&mut self) -> &Ldap {
        &self.ldap
    }
}

/// Parse the referrals from the supplied BER-encoded sequence.
pub fn parse_refs(t: StructureTag) -> Vec<String> {
    t.expect_constructed()
        .expect("referrals")
        .into_iter()
        .map(|t| t.expect_primitive().expect("octet string"))
        .map(String::from_utf8)
        .map(|s| s.expect("uri"))
        .collect()
}
