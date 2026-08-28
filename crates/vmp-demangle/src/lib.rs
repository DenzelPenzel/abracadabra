//! Safe, dependency-free demangling primitives.

mod borland;
mod cursor;
mod error;
mod function_name;
mod gnu_v3;
pub(crate) mod limits;
mod msvc;

pub use function_name::FunctionName;

/// Maximum bytes retained by any successful dialect-specific result.
pub const MAX_DEMANGLED_NAME_BYTES: usize = limits::MAX_OUTPUT_BYTES;

use std::collections::TryReserveError;

/// Demangles a decorated name, or returns it unchanged when no parser accepts it.
#[must_use]
pub fn demangle_name(raw: &str) -> FunctionName {
    try_demangle_name(raw).unwrap_or_else(|_| FunctionName::unchanged(raw))
}

/// Demangles a decorated name without an infallible allocation on unchanged fallback.
pub fn try_demangle_name(raw: &str) -> Result<FunctionName, TryReserveError> {
    if raw.is_empty() {
        return Ok(FunctionName::empty());
    }

    if let Some(name) = msvc::demangle(raw) {
        return Ok(name);
    }

    let gnu_raw = if raw.as_bytes().get(..2) == Some(b"__") {
        match raw.get(1..) {
            Some(stripped) => stripped,
            None => raw,
        }
    } else {
        raw
    };
    if let Ok(name) = gnu_v3::demangle(gnu_raw.as_bytes()) {
        return Ok(name);
    }

    if let Some(name) = borland::demangle(raw) {
        return Ok(name);
    }

    FunctionName::try_unchanged(raw)
}

fn display_string(value: &str) -> String {
    let mut displayed = String::with_capacity(value.len());
    let mut unchanged_start = 0;

    for (index, byte) in value.bytes().enumerate() {
        if byte >= 32 {
            continue;
        }

        displayed.push_str(&value[unchanged_start..index]);
        match byte {
            b'\n' => displayed.push_str("\\n"),
            b'\r' => displayed.push_str("\\r"),
            b'\t' => displayed.push_str("\\t"),
            _ => {
                displayed.push('\\');
                displayed.push_str(&byte.to_string());
            }
        }
        unchanged_start = index + 1;
    }

    if unchanged_start == 0 {
        return value.to_owned();
    }

    displayed.push_str(&value[unchanged_start..]);
    displayed
}

#[cfg(test)]
mod tests {
    use super::function_name::FunctionNameError;
    use super::{demangle_name, FunctionName};

    #[test]
    fn function_name_exposes_full_and_selector_names() {
        let name = FunctionName::new("int ns::widget()", 4).expect("valid selector offset");

        assert_eq!(name.full_name(), "int ns::widget()");
        assert_eq!(name.name(), "ns::widget()");
    }

    #[test]
    fn function_name_rejects_out_of_bounds_selector_offset() {
        let error = FunctionName::new("name", 5).expect_err("offset exceeds string length");

        assert_eq!(
            error,
            FunctionNameError::SelectorOutOfBounds {
                selector_start: 5,
                len: 4,
            }
        );
    }

    #[test]
    fn function_name_rejects_non_utf8_character_boundary() {
        let error = FunctionName::new("éclair", 1).expect_err("offset splits a UTF-8 character");

        assert_eq!(
            error,
            FunctionNameError::SelectorNotCharBoundary { selector_start: 1 }
        );
    }

    #[test]
    fn display_name_escapes_control_bytes_exactly() {
        let name = FunctionName::new("ret \0\u{1}\t\n\r\u{1f}é\\name", 4)
            .expect("selector starts on a character boundary");

        assert_eq!(name.display_name(true), "ret \\0\\1\\t\\n\\r\\31é\\name");
        assert_eq!(name.display_name(false), "\\0\\1\\t\\n\\r\\31é\\name");
    }

    #[test]
    fn display_name_preserves_utf8_byte_order_around_control_byte() {
        let name = FunctionName::unchanged("é\n界");

        assert_eq!(name.display_name(true), "é\\n界");
        assert_eq!(name.display_name(false), "é\\n界");
    }

    #[test]
    fn display_name_does_not_escape_delete() {
        let name = FunctionName::unchanged("é\u{7f}界");

        assert_eq!(name.display_name(true), "é\u{7f}界");
        assert_eq!(name.display_name(false), "é\u{7f}界");
    }

    #[test]
    fn empty_function_name_has_empty_views() {
        let name = FunctionName::empty();

        assert_eq!(name.full_name(), "");
        assert_eq!(name.name(), "");
        assert_eq!(name.display_name(true), "");
        assert_eq!(name.display_name(false), "");
    }

    #[test]
    fn demangle_name_returns_unchanged_input_when_msvc_rejects_it() {
        let name = demangle_name("plain::symbol");

        assert_eq!(name, FunctionName::unchanged("plain::symbol"));
        assert_eq!(name.full_name(), "plain::symbol");
        assert_eq!(name.name(), "plain::symbol");
    }

    #[test]
    fn public_gnu_demangler_matches_all_cpp_golden_rows_and_apple_prefix() {
        let fixture = include_str!("../tests/fixtures/cpp_demangle.tsv");
        let mut checked = 0usize;
        for line in fixture
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let mut fields = line.split('\t');
            let raw = fields.next().expect("raw field").trim_matches('"');
            let route = fields.next().expect("route field");
            let expected = fields.next().expect("expected field").trim_matches('"');
            if route != "gnu-v3" {
                continue;
            }
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
            checked += 1;
        }
        assert_eq!(checked, 93);
        assert_eq!(demangle_name("__Z1fv").name(), "f()");
        assert_eq!(demangle_name("_ZN1a"), FunctionName::unchanged("_ZN1a"));
    }

    #[test]
    fn public_borland_first_slice_matches_bundled_oracle() {
        for (raw, expected) in [
            ("@foo", "foo"),
            ("@myclass@", "myclass::"),
            ("@foo$qv", "foo()"),
            ("@foo$qi", "foo(int)"),
            ("@myclass@func$qil", "myclass::func(int, long)"),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }

        assert_eq!(demangle_name("@foo@$z"), FunctionName::unchanged("@foo@$z"));
    }

    #[test]
    fn public_borland_modifiers_and_indirections_match_bundled_oracle() {
        for (raw, expected) in [
            ("@foo$quc", "foo(unsigned char)"),
            ("@foo$qpci", "foo(char *, int)"),
            ("@foo$qri", "foo(int&)"),
            ("@afunc$qxzcupi", "afunc(const signed char, int *)"),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_borland_function_pointer_matches_bundled_oracle() {
        assert_eq!(
            demangle_name("@foo$qpqfi$d").name(),
            "foo(double (*)(float, int))"
        );
    }

    #[test]
    fn public_borland_rejects_microsoft_fastcall_spelling() {
        let raw = "@fastcall@12";
        assert_eq!(demangle_name(raw), FunctionName::unchanged(raw));
    }

    #[test]
    fn public_borland_primitive_table_matches_bundled_oracle() {
        for (raw, expected) in [
            (
                "@prim$qvcsilfdgjobeCsCi",
                "prim(, char, short, int, long, float, double, long double, long long, bool, wchar_t, ..., char16_t, char32_t)",
            ),
            ("@quals$quixiwc", "quals(unsigned int, const int, volatile char)"),
            ("@refs$qrihi", "refs(int&, int&&)"),
            (
                "@closure$qyfiyni",
                "closure(__closureint, __closureint)",
            ),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_borland_length_prefixed_tags_match_bundled_oracle() {
        assert_eq!(demangle_name("@tags$q3Foo3Bar").name(), "tags(Foo, Bar)");
        assert_eq!(
            demangle_name("@foo$q9abc"),
            FunctionName::unchanged("@foo$q9abc")
        );
    }

    #[test]
    fn public_borland_arrays_match_bundled_oracle() {
        assert_eq!(
            demangle_name("@arr$qa10$ia2$a3$c").name(),
            "arr(int[10], char[2][3])"
        );
        assert_eq!(
            demangle_name("@foo$qa10"),
            FunctionName::unchanged("@foo$qa10")
        );
    }

    #[test]
    fn public_borland_argument_backreferences_match_bundled_oracle() {
        assert_eq!(demangle_name("@back$qit1t1").name(), "back(int, int, int)");
        assert_eq!(
            demangle_name("@back$qt0"),
            FunctionName::unchanged("@back$qt0")
        );
    }

    #[test]
    fn public_borland_calling_conventions_match_bundled_oracle() {
        for (code, convention) in [
            ('c', "__cdecl"),
            ('p', "__pascal"),
            ('r', "__fastcall"),
            ('f', "__fortran"),
            ('s', "__stdcall"),
            ('y', "__syscall"),
            ('i', "__interrupt"),
            ('g', "__saveregs"),
        ] {
            let raw = format!("@calls$qq{code}i$i");
            let expected = format!("int {convention} calls(int)");
            assert_eq!(demangle_name(&raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_borland_member_pointers_match_bundled_oracle() {
        for (raw, expected) in [
            ("@memptr$qM7MyClassi", "memptr(int MyClass::*)"),
            (
                "@mfunptr$qM7MyClassqfi$d",
                "mfunptr(double (MyClass::*)(float, int))",
            ),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_borland_templates_match_bundled_oracle() {
        for (raw, expected) in [
            ("@%Vec$i%", "Vec<int>"),
            ("@%Pair$i3Foo%", "Pair<int, Foo>"),
            ("@ns@%Pair$i3Foo%", "ns::Pair<int, Foo>"),
            ("@%id$i%$qi$i", "int id<int>(int)"),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_borland_ctors_operators_and_conversions_match_bundled_oracle() {
        for (raw, expected) in [
            ("@Widget@$bctr$qv", "Widget::Widget"),
            ("@Widget@$bdtr$qv", "Widget::~Widget"),
            ("@Widget@$badd$qi", "Widget::operator +(int)"),
            ("@$bsubs$qi", "operator [](int)"),
            ("@$bnwa$qi", "operator new[](int)"),
            ("@$bdla$qpi", "operator delete[](int *)"),
            ("@Widget@$oi$qv", "Widget::operator int()"),
            ("@Widget@$op$qv", "Widget::operator  *()"),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_borland_remaining_special_symbols_match_bundled_oracle() {
        for (raw, expected) in [
            ("@6", " (huge, fastthis, rtti)"),
            ("@$xp$$i", "__tpdsc__ "),
            ("@$vsf", "__vdthk__"),
            ("@$vc1$A$B$C$", "__thunk__ [A,,B,C]"),
            ("@_$FL$@foo", "__frndl__ __linkproc__ foo"),
            ("@_$CH$@foo", "__chtbl__ __linkproc__ foo"),
            ("@_$DC$@foo", "__odtbl__ __linkproc__ foo"),
            ("@_$TL$@foo", "__thrwl__ __linkproc__ foo"),
            ("@_$ECT$@foo", "__ectbl__ __linkproc__ foo"),
            ("@@foo", "__linkproc__ foo"),
        ] {
            assert_eq!(demangle_name(raw).name(), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_dispatcher_matches_all_cpp_golden_rows_in_source_order() {
        let fixture = include_str!("../tests/fixtures/cpp_demangle.tsv");
        let mut checked = 0usize;
        for line in fixture
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let mut fields = line.split('\t');
            let raw = fields.next().expect("raw field").trim_matches('"');
            let _route = fields.next().expect("route field");
            let expected = fields.next().expect("expected field").trim_matches('"');
            assert_eq!(
                demangle_name(raw).name(),
                expected,
                "row={checked} raw={raw}"
            );
            checked += 1;
        }
        assert_eq!(checked, 107);
    }

    #[test]
    fn public_msvc_demangler_matches_all_cpp_golden_selectors() {
        for (raw, expected) in [
            (
                "?newCol@QColorPicker@?A0x3be3cb80@@QEAAXHH@Z",
                "`anonymous namespace'::QColorPicker::newCol(int,int)",
            ),
            (
                "?InitWorkspacesCollection@CDaoWorkspace@@IAEXXZ",
                "CDaoWorkspace::InitWorkspacesCollection(void)",
            ),
            (
                "?Invoke@XEventSink@COleControlSite@@UAGJJABU_GUID@@KGPAUtagDISPPARAMS@@PAUtagVARIANT@@PAUtagEXCEPINFO@@PAI@Z",
                "COleControlSite::XEventSink::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)",
            ),
            (
                "?IsNullValue@CDaoFieldExchange@@SGHPAXK@Z",
                "CDaoFieldExchange::IsNullValue(void *,unsigned long)",
            ),
            (
                "??$?0VQObject@@@?$QWeakPointer@VQObject@@@@AEAA@PEAVQObject@@_N@Z",
                "QWeakPointer<class QObject>::<class QObject>::<class QObject>(class QObject *,bool)",
            ),
        ] {
            let name = demangle_name(raw);
            assert_eq!(name.name(), expected, "raw={raw}");
            assert_eq!(name.display_name(false), expected, "raw={raw}");
        }
    }

    #[test]
    fn public_msvc_resource_rejection_falls_back_without_partial_output() {
        let raw = "?".repeat(crate::limits::MAX_INPUT_BYTES + 1);

        assert_eq!(demangle_name(&raw), FunctionName::unchanged(raw));
    }
}
