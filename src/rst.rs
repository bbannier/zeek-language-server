use std::{borrow::Cow, sync::LazyLock};

use itertools::Itertools;
use regex::Captures;

use crate::Str;

#[must_use]
pub fn markdownify(rst: &str) -> Str {
    let rst = external_link(rst);
    let rst = inline_code(&rst);
    let rst = zeek_field(&rst);
    let rst = zeek_id(&rst);
    let rst = zeek_keyword(&rst);
    let rst = zeek_see_inline(&rst);
    let rst = zeek_see_block(&rst);
    let rst = zeek_type(&rst);
    let rst = note(&rst);
    let rst = todo(&rst);

    rst.into()
}

fn external_link(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"`(\S+(\s+\S+)*)\s+<(.*)>`_{1,2}").expect("invalid regexp")
    });

    RE.replace_all(rst, "[$1]($3)")
}

fn inline_code(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"``([^`]+)``").expect("invalid regexp"));

    RE.replace_all(rst, "`$1`")
}

fn zeek_field(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r":zeek:field:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("field should be captured").as_str())
    })
}

fn zeek_id(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r":zeek:id:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
}

fn zeek_keyword(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r":zeek:keyword:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
}

fn zeek_see_inline(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r":zeek:see:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        docs_search(cap.get(1).expect("id should be captured").as_str())
    })
}

fn zeek_see_block(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?m)^\.\.\s+zeek:see::(.*)$").expect("invalid regexp")
    });

    RE.replace_all(rst, |caps: &Captures| {
        let refs = caps
            .get(1)
            .map(|ids| ids.as_str().split_whitespace().map(docs_search).join(" "))
            .unwrap_or_default();
        format!("**See also:** {refs}")
    })
}

fn zeek_type(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r":zeek:type:`([^`]+)`").expect("invalid regexp"));

    RE.replace_all(rst, |cap: &Captures| {
        format!(
            "`{}`",
            cap.get(1).expect("type should be captured").as_str()
        )
    })
}

fn note(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?m)^\.\.\s+(note::)(.*)$").expect("invalid regexp"));

    RE.replace_all(rst, "**Note:**$2")
}

fn todo(rst: &str) -> Cow<str> {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?m)^\.\.\s+(todo::)(.*)$").expect("invalid regexp"));

    RE.replace_all(rst, "**TODO:**$2")
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
            markdownify(
                "See `Wikipedia article <http://en.wikipedia.org/wiki/Levenshtein_distance>`__ for more information."
            ),
            "See [Wikipedia article](http://en.wikipedia.org/wiki/Levenshtein_distance) for more information."
        );

        assert_eq!(
            markdownify(
                "See ZeroMQ's `ZMQ_LINGER documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc24>`_ for more details."
            ),
            "See ZeroMQ's [ZMQ_LINGER documentation](http://api.zeromq.org/4-2:zmq-setsockopt#toc24) for more details."
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
    fn zeek_field() {
        assert_eq!(
            markdownify(":zeek:field:`Notice::Info$email_dest` field of that notice"),
            format!(
                "{email_dest} field of that notice",
                email_dest = docs_search("Notice::Info$email_dest")
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
    fn zeek_type() {
        assert_eq!(markdownify(":zeek:type:`foo`"), "`foo`");

        assert_eq!(
            markdownify("A :zeek:type:`foo` next to a :zeek:type:`bar`"),
            "A `foo` next to a `bar`"
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

    #[test]
    fn todo() {
        assert_eq!(
            markdownify(
                "foo

.. todo:: bar
"
            ),
            "foo

**TODO:** bar
"
        );
    }

    #[test]
    fn not_unwrap() {
        // Do not wrap simple line breaks; zeekygen comments could contain e.g.,
        // hardformatted tables and we want to preserve their formatting.
        assert_eq!(markdownify(""), "");
        assert_eq!(markdownify("ab\n"), "ab\n");
        assert_eq!(markdownify("ab\n\ncd\n"), "ab\n\ncd\n");
        assert_eq!(markdownify("ab\ncd\n"), "ab\ncd\n");
    }
}
