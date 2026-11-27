//! Exercise every public iterator operation that reaches the patched variadic
//! out-argument. CI runs these against real GLib with release optimization 3.

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use glib::variant::ToVariant;

    #[test]
    fn forward_reverse_and_last_preserve_utf8() {
        let strings = ["", "ordinary", "λ — 日本語", "🧬"];
        let value = strings.to_variant();
        let iter = value.array_iter_str().unwrap();
        assert_eq!(iter.collect::<Vec<_>>(), strings);
        let iter = value.array_iter_str().unwrap();
        assert_eq!(
            iter.rev().collect::<Vec<_>>(),
            ["🧬", "λ — 日本語", "ordinary", ""]
        );
        assert_eq!(value.array_iter_str().unwrap().last(), Some("🧬"));
    }

    #[test]
    fn mixed_iteration_visits_each_selected_item_once() {
        let value = ["zero", "one", "two", "three", "four", "five"].to_variant();
        let mut iter = value.array_iter_str().unwrap();
        assert_eq!(iter.nth(1), Some("one"));
        assert_eq!(iter.next_back(), Some("five"));
        assert_eq!(iter.next(), Some("two"));
        assert_eq!(iter.nth_back(1), Some("three"));
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next_back(), None);
    }

    #[test]
    fn empty_and_exhausted_iterators_are_fused() {
        let empty: [&str; 0] = [];
        let value = empty.to_variant();
        let mut iter = value.array_iter_str().unwrap();
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next_back(), None);
        assert_eq!(iter.nth(usize::MAX), None);
        assert_eq!(iter.nth_back(usize::MAX), None);
        assert_eq!(iter.last(), None);

        let value = ["only"].to_variant();
        let mut iter = value.array_iter_str().unwrap();
        assert_eq!(iter.next(), Some("only"));
        assert_eq!(iter.size_hint(), (0, Some(0)));
        assert_eq!(iter.next_back(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn large_indices_exhaust_without_underflow_or_overflow() {
        let value = ["first", "second"].to_variant();
        let mut iter = value.array_iter_str().unwrap();
        assert_eq!(iter.nth(usize::MAX), None);
        assert_eq!(iter.next_back(), None);
        let mut iter = value.array_iter_str().unwrap();
        assert_eq!(iter.nth_back(usize::MAX), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn borrowed_strings_remain_valid_while_variant_is_alive() {
        let long = "λx".repeat(4096);
        let value = [long.as_str(), "tail"].to_variant();
        let first = {
            let mut iter = value.array_iter_str().unwrap();
            iter.next().unwrap()
        };
        assert_eq!(first, long);
        assert_eq!(value.array_iter_str().unwrap().last(), Some("tail"));
    }
}
