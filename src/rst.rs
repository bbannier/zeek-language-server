use std::borrow::Cow;

use once_cell::sync::Lazy;
use regex::Captures;

#[must_use]
pub fn markdownify(rst: &str) -> String {
    let rst = unwrap(rst);
    let rst = external_link(&rst);
    let rst = inline_code(&rst);
    let rst = zeek_keyword(&rst);

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

fn zeek_keyword(rst: &str) -> Cow<str> {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r":zeek:keyword:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
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
}
