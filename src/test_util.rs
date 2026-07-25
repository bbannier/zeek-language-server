/// Snapshot with custom output filtering.
macro_rules! assert_debug_snapshot {
    ($($arg:tt)*) => {{
        let mut settings = insta::Settings::clone_current();
        settings.add_filter(r"InternedUri\(Id\(\d+\)\)", "InternedUri(Id(_))");
        let _guard = settings.bind_to_scope();
        insta::assert_debug_snapshot!($($arg)*)
    }};
}

pub(crate) use assert_debug_snapshot;
