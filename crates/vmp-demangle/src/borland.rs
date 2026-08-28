use crate::FunctionName;

const MAX_INPUT_BYTES: usize = 254;
const MAX_OUTPUT_BYTES: usize = 1023;
const MAX_NESTING_DEPTH: usize = 6;
const MAX_ARGUMENTS: usize = 250;

pub(super) fn demangle(raw: &str) -> Option<FunctionName> {
    let bytes = raw.as_bytes();
    if bytes.len() > MAX_INPUT_BYTES || bytes.first() != Some(&b'@') {
        return None;
    }

    let mut digit_start = bytes.len();
    while digit_start > 0 && bytes.get(digit_start - 1).is_some_and(u8::is_ascii_digit) {
        digit_start -= 1;
    }
    if digit_start < bytes.len() && digit_start > 1 && bytes.get(digit_start - 1) == Some(&b'@') {
        return None;
    }

    let mut parser = Parser {
        raw,
        bytes,
        position: 1,
        depth: 0,
        template_name: false,
        last_qualifier: None,
        output: Output::new(),
    };
    parser.parse()?;
    FunctionName::new(parser.output.finish(), 0).ok()
}

struct Parser<'raw> {
    raw: &'raw str,
    bytes: &'raw [u8],
    position: usize,
    depth: usize,
    template_name: bool,
    last_qualifier: Option<(usize, usize)>,
    output: Output,
}

impl Parser<'_> {
    fn parse(&mut self) -> Option<()> {
        self.parse_name()?;
        if self.position == self.bytes.len() {
            return Some(());
        }

        self.consume(b'$')?;
        self.consume(b'q')?;
        self.parse_arguments()?;
        if self.template_name && self.byte() == Some(b'$') {
            self.position = self.position.checked_add(1)?;
            let return_type = self.parse_type()?;
            let name = std::mem::replace(&mut self.output, Output::new()).finish();
            let mut output = Output::new();
            output.push_str(&return_type)?;
            output.push_str(" ")?;
            output.push_str(&name)?;
            self.output = output;
        }
        (self.position == self.bytes.len()).then_some(())
    }

    fn parse_name(&mut self) -> Option<()> {
        loop {
            if self.position == 1 && self.bytes.get(self.position..) == Some(b"6") {
                self.output.push_str(" (huge, fastthis, rtti)")?;
                self.position = self.bytes.len();
                return Some(());
            }
            if self.byte() == Some(b'@') {
                self.position = self.position.checked_add(1)?;
                let name = self.parse_remaining_identifier()?;
                self.output.push_str("__linkproc__ ")?;
                self.output.push_str(&name)?;
                return Some(());
            }
            if self.bytes.get(self.position..self.position.checked_add(2)?) == Some(b"_$") {
                self.position = self.position.checked_add(2)?;
                let code_start = self.position;
                while self.byte().is_some_and(|byte| byte.is_ascii_uppercase()) {
                    self.position = self.position.checked_add(1)?;
                }
                let code = self.raw.get(code_start..self.position)?;
                self.consume(b'$')?;
                self.consume(b'@')?;
                let name = self.parse_remaining_identifier()?;
                let prefix = match code {
                    "FL" => "__frndl__ ",
                    "CH" => "__chtbl__ ",
                    "DC" => "__odtbl__ ",
                    "TL" => "__thrwl__ ",
                    "ECT" => "__ectbl__ ",
                    _ => return None,
                };
                self.output.push_str(prefix)?;
                self.output.push_str("__linkproc__ ")?;
                self.output.push_str(&name)?;
                return Some(());
            }
            if self.byte() == Some(b'$') {
                self.parse_special_name()?;
                return Some(());
            }
            if self.byte() == Some(b'%') {
                self.position = self.position.checked_add(1)?;
                let start = self.position;
                while !matches!(self.byte(), None | Some(b'$' | b'@' | b'%')) {
                    self.position = self.position.checked_add(1)?;
                }
                if self.position == start || self.byte() != Some(b'$') {
                    return None;
                }
                let name_bytes = self.bytes.get(start..self.position)?;
                if !name_bytes
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                    || !name_bytes
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    return None;
                }
                let name = self.raw.get(start..self.position)?;
                self.position = self.position.checked_add(1)?;
                let arguments = self.parse_argument_sequence(Some(b'%'))?;
                self.consume(b'%')?;
                self.output.push_str(name)?;
                self.output.push_str("<")?;
                self.output.push_str(&arguments)?;
                self.output.push_str(">")?;
                self.template_name = true;
                match self.byte() {
                    Some(b'@') => {
                        self.position = self.position.checked_add(1)?;
                        self.output.push_str("::")?;
                        if self.position == self.bytes.len() {
                            return Some(());
                        }
                    }
                    Some(b'$') | None => return Some(()),
                    _ => return None,
                }
                continue;
            }

            let start = self.position;
            while !matches!(self.byte(), None | Some(b'@' | b'$')) {
                self.position = self.position.checked_add(1)?;
            }
            if self.position == start {
                return None;
            }
            if start == 1 && self.bytes.get(start).is_some_and(u8::is_ascii_digit) {
                return None;
            }

            self.output.push_str(self.raw.get(start..self.position)?)?;
            match self.byte() {
                Some(b'@') => {
                    self.last_qualifier = Some((start, self.position));
                    self.position = self.position.checked_add(1)?;
                    self.output.push_str("::")?;
                    if self.position == self.bytes.len() {
                        return Some(());
                    }
                }
                Some(b'$') | None => return Some(()),
                _ => return None,
            }
        }
    }

    fn parse_remaining_identifier(&mut self) -> Option<String> {
        let start = self.position;
        let bytes = self.bytes.get(start..)?;
        if !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return None;
        }
        let name = self.raw.get(start..)?;
        let mut output = Output::new();
        output.push_str(name)?;
        self.position = self.bytes.len();
        Some(output.finish())
    }

    fn parse_special_name(&mut self) -> Option<()> {
        self.consume(b'$')?;
        match self.byte()? {
            b'b' => {
                self.position = self.position.checked_add(1)?;
                let start = self.position;
                while !matches!(self.byte(), None | Some(b'$')) {
                    self.position = self.position.checked_add(1)?;
                }
                let code = self.raw.get(start..self.position)?;
                match code {
                    "ctr" | "dtr" => {
                        let (owner_start, owner_end) = self.last_qualifier?;
                        let owner = self.raw.get(owner_start..owner_end)?;
                        if code == "dtr" {
                            self.output.push_str("~")?;
                        }
                        self.output.push_str(owner)?;
                        if self.bytes.get(self.position..) != Some(b"$qv") {
                            return None;
                        }
                        self.position = self.bytes.len();
                    }
                    "add" => self.output.push_str("operator +")?,
                    "subs" => self.output.push_str("operator []")?,
                    "nwa" => self.output.push_str("operator new[]")?,
                    "dla" => self.output.push_str("operator delete[]")?,
                    _ => return None,
                }
            }
            b'x' => {
                if self.bytes.get(self.position..) != Some(b"xp$$i") {
                    return None;
                }
                self.output.push_str("__tpdsc__ ")?;
                self.position = self.bytes.len();
            }
            b'v' if self.bytes.get(self.position..) == Some(b"vsf") => {
                self.output.push_str("__vdthk__")?;
                self.position = self.bytes.len();
            }
            b'v' => {
                self.position = self.position.checked_add(1)?;
                self.consume(b'c')?;
                if !self.byte()?.is_ascii_digit() {
                    return None;
                }
                self.position = self.position.checked_add(1)?;
                self.consume(b'$')?;
                let first_start = self.position;
                while !matches!(self.byte(), None | Some(b'$')) {
                    self.position = self.position.checked_add(1)?;
                }
                let first = self.raw.get(first_start..self.position)?;
                self.consume(b'$')?;
                let second_start = self.position;
                while !matches!(self.byte(), None | Some(b'$')) {
                    self.position = self.position.checked_add(1)?;
                }
                let second = self.raw.get(second_start..self.position)?;
                self.consume(b'$')?;
                let third_start = self.position;
                while !matches!(self.byte(), None | Some(b'$')) {
                    self.position = self.position.checked_add(1)?;
                }
                let third = self.raw.get(third_start..self.position)?;
                self.consume(b'$')?;
                if self.position != self.bytes.len() {
                    return None;
                }
                self.output.push_str("__thunk__ [")?;
                self.output.push_str(first)?;
                self.output.push_str(",,")?;
                self.output.push_str(second)?;
                self.output.push_str(",")?;
                self.output.push_str(third)?;
                self.output.push_str("]")?;
            }
            b'o' => {
                self.position = self.position.checked_add(1)?;
                match self.byte()? {
                    b'i' => self.output.push_str("operator int")?,
                    b'p' => self.output.push_str("operator  *")?,
                    _ => return None,
                }
                self.position = self.position.checked_add(1)?;
                if self.byte() != Some(b'$') {
                    return None;
                }
            }
            _ => return None,
        }
        Some(())
    }

    fn parse_arguments(&mut self) -> Option<()> {
        if self.byte() == Some(b'q') {
            self.position = self.position.checked_add(1)?;
            let convention = match self.byte()? {
                b'c' => "__cdecl",
                b'p' => "__pascal",
                b'r' => "__fastcall",
                b'f' => "__fortran",
                b's' => "__stdcall",
                b'y' => "__syscall",
                b'i' => "__interrupt",
                b'g' => "__saveregs",
                _ => return None,
            };
            self.position = self.position.checked_add(1)?;
            let arguments = self.parse_argument_sequence(Some(b'$'))?;
            self.consume(b'$')?;
            let return_type = self.parse_type()?;

            let name = std::mem::replace(&mut self.output, Output::new()).finish();
            let mut output = Output::new();
            output.push_str(&return_type)?;
            output.push_str(" ")?;
            output.push_str(convention)?;
            output.push_str(" ")?;
            output.push_str(&name)?;
            output.push_str("(")?;
            output.push_str(&arguments)?;
            output.push_str(")")?;
            self.output = output;
            return Some(());
        }

        self.output.push_str("(")?;
        let terminator = self.template_name.then_some(b'$');
        let arguments = self.parse_argument_sequence(terminator)?;
        self.output.push_str(&arguments)?;
        self.output.push_str(")")
    }

    fn parse_argument_sequence(&mut self, terminator: Option<u8>) -> Option<String> {
        let mut output = Output::new();
        let mut table: Vec<String> = Vec::new();
        let void_is_sentinel = if self.byte() == Some(b'v') {
            match terminator {
                Some(terminator) => {
                    self.bytes.get(self.position.checked_add(1)?) == Some(&terminator)
                }
                None => self.position.checked_add(1)? == self.bytes.len(),
            }
        } else {
            false
        };
        if void_is_sentinel {
            self.position = self.position.checked_add(1)?;
            return Some(output.finish());
        }

        loop {
            match (self.byte(), terminator) {
                (Some(byte), Some(terminator)) if byte == terminator => break,
                (None, None) => break,
                (None, Some(_)) => return None,
                _ => {}
            }

            let rendered = if self.byte() == Some(b't') {
                self.position = self.position.checked_add(1)?;
                let code = self.byte()?;
                let index = match code {
                    b'1'..=b'9' => usize::from(code - b'1'),
                    b'a'..=b'z' => usize::from(code - b'a').checked_add(9)?,
                    _ => return None,
                };
                self.position = self.position.checked_add(1)?;
                let referenced = table.get(index)?;
                let mut rendered = Output::new();
                rendered.push_str(referenced)?;
                rendered.finish()
            } else {
                self.parse_type()?
            };

            if !table.is_empty() {
                output.push_str(", ")?;
            }
            output.push_str(&rendered)?;
            if table.len() >= MAX_ARGUMENTS {
                return None;
            }
            table.try_reserve_exact(1).ok()?;
            table.push(rendered);
        }
        Some(output.finish())
    }

    fn parse_simple_tag_name(&mut self) -> Option<String> {
        let mut length = 0usize;
        let digit_start = self.position;
        while let Some(byte) = self.byte().filter(u8::is_ascii_digit) {
            length = length
                .checked_mul(10)?
                .checked_add(usize::from(byte - b'0'))?;
            self.position = self.position.checked_add(1)?;
        }
        if self.position == digit_start || length == 0 {
            return None;
        }
        let start = self.position;
        let end = start.checked_add(length)?;
        let bytes = self.bytes.get(start..end)?;
        if !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return None;
        }
        let name = self.raw.get(start..end)?;
        let mut output = Output::new();
        output.push_str(name)?;
        self.position = end;
        Some(output.finish())
    }

    fn parse_type(&mut self) -> Option<String> {
        let attempted = self.depth.checked_add(1)?;
        if attempted > MAX_NESTING_DEPTH {
            return None;
        }
        let previous_depth = self.depth;
        self.depth = attempted;
        let result = self.parse_type_inner();
        self.depth = previous_depth;
        result
    }

    fn parse_type_inner(&mut self) -> Option<String> {
        let mut output = Output::new();
        let mut suffixes = [0u8; MAX_INPUT_BYTES];
        let mut suffix_count = 0usize;

        loop {
            match self.byte()? {
                b'x' if self.bytes.get(self.position.checked_add(1)?) == Some(&b'p') => {
                    self.position = self.position.checked_add(1)?;
                    *suffixes.get_mut(suffix_count)? = b'x';
                    suffix_count = suffix_count.checked_add(1)?;
                }
                b'x' => {
                    self.position = self.position.checked_add(1)?;
                    output.push_str("const ")?;
                }
                b'z' => {
                    self.position = self.position.checked_add(1)?;
                    output.push_str("signed ")?;
                }
                b'w' if self.bytes.get(self.position.checked_add(1)?) == Some(&b'p') => {
                    self.position = self.position.checked_add(1)?;
                    *suffixes.get_mut(suffix_count)? = b'w';
                    suffix_count = suffix_count.checked_add(1)?;
                }
                b'w' => {
                    self.position = self.position.checked_add(1)?;
                    output.push_str("volatile ")?;
                }
                b'y' => {
                    let closure = self.bytes.get(self.position.checked_add(1)?)?;
                    if !matches!(closure, b'f' | b'n') {
                        return None;
                    }
                    self.position = self.position.checked_add(2)?;
                    output.push_str("__closure")?;
                }
                b'u' if self.bytes.get(self.position.checked_add(1)?) == Some(&b'p') => {
                    self.position = self.position.checked_add(2)?;
                    *suffixes.get_mut(suffix_count)? = b'p';
                    suffix_count = suffix_count.checked_add(1)?;
                }
                b'u' => {
                    self.position = self.position.checked_add(1)?;
                    output.push_str("unsigned ")?;
                }
                byte @ (b'p' | b'r' | b'h') => {
                    self.position = self.position.checked_add(1)?;
                    *suffixes.get_mut(suffix_count)? = byte;
                    suffix_count = suffix_count.checked_add(1)?;
                }
                _ => break,
            }
        }

        if self.byte() == Some(b'M') {
            if !output.is_empty() || suffix_count != 0 {
                return None;
            }
            self.position = self.position.checked_add(1)?;
            let class = self.parse_simple_tag_name()?;
            if self.byte() == Some(b'q') {
                self.position = self.position.checked_add(1)?;
                let arguments = self.parse_argument_sequence(Some(b'$'))?;
                self.consume(b'$')?;
                let return_type = self.parse_type()?;
                output.push_str(&return_type)?;
                output.push_str(" (")?;
                output.push_str(&class)?;
                output.push_str("::*)(")?;
                output.push_str(&arguments)?;
                output.push_str(")")?;
            } else {
                let member = self.parse_type()?;
                output.push_str(&member)?;
                output.push_str(" ")?;
                output.push_str(&class)?;
                output.push_str("::*")?;
            }
            return Some(output.finish());
        }

        if self.byte() == Some(b'a') {
            if !output.is_empty() || suffix_count != 0 {
                return None;
            }
            let mut dimensions = Output::new();
            while self.byte() == Some(b'a') {
                self.position = self.position.checked_add(1)?;
                let start = self.position;
                while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.position = self.position.checked_add(1)?;
                }
                if self.position == start {
                    return None;
                }
                let dimension = self.raw.get(start..self.position)?;
                self.consume(b'$')?;
                dimensions.push_str("[")?;
                dimensions.push_str(dimension)?;
                dimensions.push_str("]")?;
            }
            let element = self.parse_type()?;
            output.push_str(&element)?;
            output.push_str(&dimensions.finish())?;
            return Some(output.finish());
        }

        if self.byte() == Some(b'q') {
            if !output.is_empty() || suffix_count == 0 {
                return None;
            }
            self.position = self.position.checked_add(1)?;
            let arguments = self.parse_argument_sequence(Some(b'$'))?;
            self.consume(b'$')?;
            let return_type = self.parse_type()?;

            output.push_str(&return_type)?;
            output.push_str(" (")?;
            for suffix in suffixes.get(..suffix_count)?.iter().rev() {
                match suffix {
                    b'p' => output.push_str("*")?,
                    b'r' => output.push_str("&")?,
                    _ => return None,
                }
            }
            output.push_str(")(")?;
            output.push_str(&arguments)?;
            output.push_str(")")?;
            return Some(output.finish());
        }

        if self.byte()?.is_ascii_digit() {
            let mut length = 0usize;
            while let Some(byte) = self.byte().filter(u8::is_ascii_digit) {
                length = length
                    .checked_mul(10)?
                    .checked_add(usize::from(byte - b'0'))?;
                self.position = self.position.checked_add(1)?;
            }
            if length == 0 {
                return None;
            }
            let start = self.position;
            let end = start.checked_add(length)?;
            let name_bytes = self.bytes.get(start..end)?;
            if !name_bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                || !name_bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return None;
            }
            let name = self.raw.get(start..end)?;
            output.push_str(name)?;
            self.position = end;
        } else {
            let rendered = match self.byte()? {
                b'b' => "wchar_t",
                b'c' => "char",
                b'd' => "double",
                b'e' => "...",
                b'f' => "float",
                b'g' => "long double",
                b'i' => "int",
                b'j' => "long long",
                b'l' => "long",
                b'o' => "bool",
                b's' => "short",
                b'v' => "",
                b'C' => match self.bytes.get(self.position.checked_add(1)?)? {
                    b's' => "char16_t",
                    b'i' => "char32_t",
                    _ => return None,
                },
                _ => return None,
            };
            self.position =
                self.position
                    .checked_add(if self.byte() == Some(b'C') { 2 } else { 1 })?;
            output.push_str(rendered)?;
        }

        for suffix in suffixes.get(..suffix_count)?.iter().rev() {
            match suffix {
                b'p' => output.push_str(" *")?,
                b'r' => output.push_str("&")?,
                b'h' => output.push_str("&&")?,
                b'x' => output.push_str(" const")?,
                b'w' => output.push_str(" volatile")?,
                _ => return None,
            }
        }
        Some(output.finish())
    }

    fn consume(&mut self, expected: u8) -> Option<()> {
        if self.byte()? != expected {
            return None;
        }
        self.position = self.position.checked_add(1)?;
        Some(())
    }

    fn byte(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
}

struct Output {
    value: String,
}

impl Output {
    fn new() -> Self {
        Self {
            value: String::new(),
        }
    }

    fn push_str(&mut self, value: &str) -> Option<()> {
        let new_len = self.value.len().checked_add(value.len())?;
        if new_len > MAX_OUTPUT_BYTES {
            return None;
        }
        self.value.try_reserve_exact(value.len()).ok()?;
        self.value.push_str(value);
        Some(())
    }

    fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn finish(self) -> String {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::{demangle, MAX_NESTING_DEPTH};

    fn nested_function_pointer(depth: usize) -> String {
        let mut encoded = String::from("i");
        for _ in 0..depth {
            encoded = format!("pqv${encoded}");
        }
        format!("@deep$q{encoded}")
    }

    #[test]
    fn borland_fixture_matches_all_accepted_and_rejected_oracle_rows() {
        let fixture = include_str!("../tests/fixtures/borland_corpus.tsv");
        let mut exact = 0usize;
        let mut pending = 0usize;
        let mut native_rejected = 0usize;
        let mut mismatch = Vec::new();

        for line in fixture
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let mut fields = line.splitn(4, '\t');
            let raw = fields.next().expect("raw field").trim_matches('"');
            let _status = fields.next().expect("status field");
            let accepted = fields.next().expect("accepted field") == "true";
            let expected = fields.next().expect("rendered field").trim_matches('"');
            match (accepted, demangle(raw)) {
                (true, Some(actual)) if actual.full_name() == expected => exact += 1,
                (true, None) => pending += 1,
                (false, None) => native_rejected += 1,
                (_, actual) => mismatch.push(format!(
                    "raw={raw:?} accepted={accepted} expected={expected:?} actual={actual:?}"
                )),
            }
        }

        eprintln!(
            "Borland fixture: exact={exact}/46, pending={pending}, native_rejected={native_rejected}/11, mismatch={}; examples={:#?}",
            mismatch.len(),
            mismatch.iter().take(4).collect::<Vec<_>>()
        );
        assert_eq!(exact, 46, "all accepted Borland rows must remain exact");
        assert_eq!(pending, 0, "no accepted Borland row may remain pending");
        assert_eq!(
            native_rejected, 11,
            "all rejected rows must remain rejected"
        );
        assert!(mismatch.is_empty());
    }

    #[test]
    fn recursive_function_pointer_depth_accepts_limit_and_rejects_one_over() {
        let exact = nested_function_pointer(MAX_NESTING_DEPTH - 1);
        assert!(demangle(&exact).is_some());

        let over = nested_function_pointer(MAX_NESTING_DEPTH);
        assert!(demangle(&over).is_none());
    }

    #[test]
    fn recursive_function_pointer_boundary_is_safe_on_64_kib_stack_subprocess() {
        const CHILD_ENV: &str = "VMP_BORLAND_SMALL_STACK_CHILD";
        const TEST_NAME: &str =
            "borland::tests::recursive_function_pointer_boundary_is_safe_on_64_kib_stack_subprocess";

        if std::env::var_os(CHILD_ENV).is_some() {
            let child = std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(|| {
                    let exact = nested_function_pointer(MAX_NESTING_DEPTH - 1);
                    assert!(demangle(&exact).is_some());
                    let over = nested_function_pointer(MAX_NESTING_DEPTH);
                    assert!(demangle(&over).is_none());
                })
                .expect("small-stack parser thread must start");
            child
                .join()
                .expect("Borland parser must not abort on the bounded stack");
            return;
        }

        let current_test_binary =
            std::env::current_exe().expect("current unit-test executable must be available");
        let status = std::process::Command::new(current_test_binary)
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .status()
            .expect("small-stack subprocess must start");
        assert!(status.success(), "small-stack subprocess failed: {status}");
    }

    #[test]
    fn recursive_function_pointer_requires_delimiter_and_return_type() {
        assert!(demangle("@deep$qpqv").is_none());
        assert!(demangle("@deep$qpqv$").is_none());
    }
}
