use once_cell::sync::Lazy;

#[must_use]
pub fn markdownify(rst: &str) -> String {
    replace_external_link(rst)
}

fn replace_external_link(rst: &str) -> String {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"`(\S+(\s+\S+)*)\s+<(.*)>`__").expect("invalid regexp"));

    RE.replace(rst, "[$1]($3)").into()
}

#[cfg(test)]
mod test {
    use super::markdownify;

    #[test]
    fn replace_external_link() {
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
}
