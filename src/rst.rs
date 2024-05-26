use std::borrow::Cow;

use itertools::Itertools;
use once_cell::sync::Lazy;
use regex::Captures;

#[must_use]
pub fn markdownify(rst: &str) -> String {
    let rst = unwrap(rst);
    let rst = external_link(&rst);
    let rst = inline_code(&rst);
    let rst = zeek_id(&rst);
    let rst = zeek_keyword(&rst);
    let rst = zeek_see_inline(&rst);
    let rst = zeek_see_block(&rst);
    let rst = note(&rst);

    rst.into_owned()
}

fn external_link(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"`(\S+(\s+\S+)*)\s+<(.*)>`__").expect("invalid regexp"));

    RE.replace_all(rst, "[$1]($3)")
}

fn inline_code(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"``([^`]+)``").expect("invalid regexp"));

    RE.replace_all(rst, "`$1`")
}

fn unwrap(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(\S)(\n)(\S)").expect("invalid regexp"));

    RE.replace_all(rst, "$1 $3")
}

fn zeek_id(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r":zeek:id:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
}

fn zeek_keyword(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r":zeek:keyword:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
}

fn zeek_see_inline(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r":zeek:see:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
}

fn zeek_see_block(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?m)^\.\.\s+zeek:see::(.*)$").expect("invalid regexp"));

    RE.replace_all(rst, |caps: &Captures| {
        let refs = caps
            .get(1)
            .map(|ids| ids.as_str().split_whitespace().map(docs_search).join(" "))
            .unwrap_or_default();
        format!("**See also:** {refs}")
    })
}

fn note(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?m)^\.\.\s+(note::)(.*)$").expect("invalid regexp"));

    RE.replace_all(rst, "**Note:**$2")
}

fn docs_search(id: &str) -> String {
    format!("[`{id}`](https://docs.zeek.org/en/master/search.html?q={id})")
}

#[cfg(test)]
mod test {
    use super::{docs_search, markdownify};

    #[test]
    fn external_link() {
        assert_eq!(
            markdownify("`foo <https://example.com>`__"),
            "[foo](https://example.com)"
        );
        assert_eq!(
            markdownify("`foo\n<https://example.com>`__"),
            "[foo](https://example.com)"
        );
        assert_eq!(
            markdownify("See `Wikipedia article <http://en.wikipedia.org/wiki/Levenshtein_distance>`__ for more information."),
            "See [Wikipedia article](http://en.wikipedia.org/wiki/Levenshtein_distance) for more information."
        );
    }

    #[test]
    fn inline_code() {
        assert_eq!(markdownify("``1``"), "`1`");
        assert_eq!(markdownify("``1 + 2``"), "`1 + 2`");
        assert_eq!(markdownify("``1`` and ``2``"), "`1` and `2`");
        assert_eq!(
            markdownify("``1 + 2`` and ``3 + 4``"),
            "`1 + 2` and `3 + 4`"
        );
    }

    #[test]
    fn unwrap() {
        assert_eq!(markdownify(""), "");
        assert_eq!(markdownify("ab\n"), "ab\n");
        assert_eq!(markdownify("ab\n\ncd\n"), "ab\n\ncd\n");
        assert_eq!(markdownify("ab\ncd\n"), "ab cd\n");
    }

    #[test]
    fn zeek_id() {
        assert_eq!(
            markdownify(":zeek:id:`network_time`"),
            docs_search("network_time")
        );

        assert_eq!(
            markdownify("A :zeek:id:`foo` next to a :zeek:id:`bar`"),
            format!(
                "A {foo} next to a {bar}",
                foo = docs_search("foo"),
                bar = docs_search("bar")
            )
        );
    }

    #[test]
    fn zeek_keyword() {
        assert_eq!(
            markdownify(":zeek:keyword:`schedule`"),
            docs_search("schedule")
        );

        assert_eq!(
            markdownify("A :zeek:keyword:`foo` next to a :zeek:keyword:`bar`"),
            format!(
                "A {foo} next to a {bar}",
                foo = docs_search("foo"),
                bar = docs_search("bar")
            )
        );
    }

    #[test]
    fn zeek_see_inline() {
        assert_eq!(markdownify(":zeek:see:`foo`"), docs_search("foo"));

        assert_eq!(
            markdownify("A :zeek:see:`foo` next to a :zeek:see:`bar`"),
            format!(
                "A {foo} next to a {bar}",
                foo = docs_search("foo"),
                bar = docs_search("bar")
            )
        );
    }

    #[test]
    fn zeek_see_block() {
        assert_eq!(
            markdownify(".. zeek:see:: abc xyz"),
            format!(
                "**See also:** {abc} {xyz}",
                abc = docs_search("abc"),
                xyz = docs_search("xyz")
            )
        );

        assert_eq!(
            markdownify(
                "Some text

.. zeek:see:: abc xyz

More text
"
            ),
            format!(
                "Some text

**See also:** {abc} {xyz}

More text
",
                abc = docs_search("abc"),
                xyz = docs_search("xyz")
            )
        );
    }

    #[test]
    fn note() {
        assert_eq!(
            markdownify(
                "foo

.. note:: bar
"
            ),
            "foo

**Note:** bar
"
        );

        assert_eq!(
            markdownify(
                "foo

.. note::

   foo bar
   baz
"
            ),
            // We do not clean up indention of the note block under the assumption that a
            // markdown-capable client would not display it.
            "foo

**Note:**

   foo bar
   baz
"
        );
    }
}
