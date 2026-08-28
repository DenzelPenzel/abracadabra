use crate::cursor::Cursor;
use crate::error::ParseFailure;
use crate::function_name::{FunctionName, FunctionNameError};
use crate::limits::{
    MAX_ARGUMENTS, MAX_INPUT_BYTES, MAX_MSVC_NESTING_DEPTH as MAX_NESTING_DEPTH, MAX_OUTPUT_BYTES,
    MAX_STANDALONE_ARRAY_DIMENSIONS,
};
use crate::msvc::flags::{
    UNDNAME_NAME_ONLY, UNDNAME_NO_ACCESS_SPECIFIERS, UNDNAME_NO_ALLOCATION_LANGUAGE,
    UNDNAME_NO_ARGUMENTS, UNDNAME_NO_COMPLEX_TYPE, UNDNAME_NO_FUNCTION_RETURNS,
    UNDNAME_NO_LEADING_UNDERSCORES, UNDNAME_NO_MEMBER_TYPE, UNDNAME_NO_MS_KEYWORDS,
    UNDNAME_NO_THISTYPE,
};
use crate::msvc::state::{AttemptBudget, RefArray};

const MAX_ENCODED_NUMBER: u32 = i32::MAX as u32;

pub(super) fn parse_number(
    cursor: &mut Cursor<'_>,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let start = cursor.position();
    let negative = if cursor.peek(0) == Some(b'?') {
        cursor.advance(1)?;
        true
    } else {
        false
    };

    match cursor.peek(0) {
        Some(byte @ b'0'..=b'8') => {
            cursor.advance(1)?;
            render_number(u32::from(byte - b'0' + 1), negative, budget)
        }
        Some(b'9') => {
            cursor.advance(1)?;
            render_number(10, negative, budget)
        }
        Some(b'A'..=b'P') => parse_hexadecimal_number(cursor, start, negative, budget),
        found => Err(ParseFailure::InvalidNumberStart {
            offset: cursor.position(),
            found,
        }),
    }
}

fn parse_hexadecimal_number(
    cursor: &mut Cursor<'_>,
    start: usize,
    negative: bool,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let mut value = 0_u32;
    while let Some(byte @ b'A'..=b'P') = cursor.peek(0) {
        let offset = cursor.position();
        cursor.advance(1)?;
        let digit = u32::from(byte - b'A');
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .filter(|value| *value <= MAX_ENCODED_NUMBER)
            .ok_or(ParseFailure::NumberOverflow {
                start,
                offset,
                max: MAX_ENCODED_NUMBER,
            })?;
    }

    if cursor.peek(0) != Some(b'@') {
        return Err(ParseFailure::MissingNumberTerminator {
            offset: cursor.position(),
            found: cursor.peek(0),
        });
    }
    cursor.advance(1)?;
    render_number(value, negative, budget)
}

fn render_number(
    mut value: u32,
    negative: bool,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let mut bytes = [0_u8; 11];
    let mut start = bytes.len();
    loop {
        start = start
            .checked_sub(1)
            .ok_or(ParseFailure::InvalidLiteralRange {
                start,
                end: bytes.len(),
            })?;
        let bytes_len = bytes.len();
        let slot = bytes
            .get_mut(start)
            .ok_or(ParseFailure::InvalidLiteralRange {
                start,
                end: bytes_len,
            })?;
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if negative {
        start = start
            .checked_sub(1)
            .ok_or(ParseFailure::InvalidLiteralRange {
                start,
                end: bytes.len(),
            })?;
        let bytes_len = bytes.len();
        let slot = bytes
            .get_mut(start)
            .ok_or(ParseFailure::InvalidLiteralRange {
                start,
                end: bytes_len,
            })?;
        *slot = b'-';
    }
    let rendered_bytes = bytes
        .get(start..)
        .ok_or(ParseFailure::InvalidLiteralRange {
            start,
            end: bytes.len(),
        })?;
    let rendered =
        std::str::from_utf8(rendered_bytes).map_err(|_| ParseFailure::InvalidLiteralRange {
            start,
            end: bytes.len(),
        })?;
    budget.copy_string(rendered)
}

pub(super) fn ordinary_primitive_type(byte: u8) -> Option<&'static str> {
    match byte {
        b'C' => Some("signed char"),
        b'D' => Some("char"),
        b'E' => Some("unsigned char"),
        b'F' => Some("short"),
        b'G' => Some("unsigned short"),
        b'H' => Some("int"),
        b'I' => Some("unsigned int"),
        b'J' => Some("long"),
        b'K' => Some("unsigned long"),
        b'M' => Some("float"),
        b'N' => Some("double"),
        b'O' => Some("long double"),
        b'X' => Some("void"),
        b'Z' => Some("..."),
        _ => None,
    }
}

pub(super) fn extended_primitive_type(byte: u8) -> Option<&'static str> {
    match byte {
        b'D' => Some("__int8"),
        b'E' => Some("unsigned __int8"),
        b'F' => Some("__int16"),
        b'G' => Some("unsigned __int16"),
        b'H' => Some("__int32"),
        b'I' => Some("unsigned __int32"),
        b'J' => Some("__int64"),
        b'K' => Some("unsigned __int64"),
        b'L' => Some("__int128"),
        b'M' => Some("unsigned __int128"),
        b'N' => Some("bool"),
        b'W' => Some("wchar_t"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatorAction {
    Constructor,
    Destructor,
    Conversion,
    Dynamic(DynamicOperator),
    ImmediateString(&'static str),
    Rtti(RttiOperator),
    Simple(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DynamicOperator {
    Initializer,
    AtexitDestructor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RttiOperator {
    TypeDescriptor,
    BaseClassDescriptor,
    BaseClassArray,
    ClassHierarchyDescriptor,
    CompleteObjectLocator,
}

impl OperatorAction {
    fn base_name(self) -> Option<&'static str> {
        match self {
            Self::Constructor
            | Self::Destructor
            | Self::Dynamic(_)
            | Self::Rtti(RttiOperator::TypeDescriptor | RttiOperator::BaseClassDescriptor) => None,
            Self::Conversion => Some("operator "),
            Self::Rtti(RttiOperator::BaseClassArray) => Some("`RTTI Base Class Array'"),
            Self::Rtti(RttiOperator::ClassHierarchyDescriptor) => {
                Some("`RTTI Class Hierarchy Descriptor'")
            }
            Self::Rtti(RttiOperator::CompleteObjectLocator) => {
                Some("`RTTI Complete Object Locator'")
            }
            Self::ImmediateString(name) | Self::Simple(name) => Some(name),
        }
    }

    fn is_constructor_or_destructor(self) -> bool {
        matches!(self, Self::Constructor | Self::Destructor)
    }

    fn has_no_function_return(self) -> bool {
        matches!(self, Self::Rtti(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThunkKind {
    Adjustor,
    Vtordisp,
    Vtordispex,
    Vcall,
}

#[derive(Debug, Clone, Copy)]
struct MethodKind {
    access: &'static str,
    member_type: &'static str,
    has_this: bool,
    has_return: bool,
    has_arguments: bool,
    thunk: Option<ThunkKind>,
}

impl MethodKind {
    fn decode(accmem: u8) -> Self {
        let access = match accmem {
            b'A'..=b'H' => "private: ",
            b'I'..=b'P' => "protected: ",
            b'Q'..=b'X' => "public: ",
            _ => "",
        };
        let (member_type, has_this, thunk) = match accmem {
            b'C' | b'D' | b'K' | b'L' | b'S' | b'T' => ("static ", false, None),
            b'E' | b'F' | b'M' | b'N' | b'U' | b'V' => ("virtual ", true, None),
            b'G' | b'H' | b'O' | b'P' | b'W' | b'X' => {
                ("virtual ", true, Some(ThunkKind::Adjustor))
            }
            b'Y' | b'Z' => ("", false, None),
            _ => ("", true, None),
        };
        Self {
            access,
            member_type,
            has_this,
            has_return: true,
            has_arguments: true,
            thunk,
        }
    }

    fn thunk(access: &'static str, thunk: ThunkKind) -> Self {
        let virtual_method = !matches!(thunk, ThunkKind::Vcall);
        Self {
            access,
            member_type: if virtual_method { "virtual " } else { "" },
            has_this: virtual_method,
            has_return: virtual_method,
            has_arguments: virtual_method,
            thunk: Some(thunk),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Datatype {
    left: String,
    right: Option<String>,
}

struct MsvcParser<'input> {
    cursor: Cursor<'input>,
    flags: u16,
    names: RefArray,
    stack: RefArray,
    budget: AttemptBudget,
    depth: usize,
    name_pos: usize,
}

pub(super) fn demangle(raw: &str, flags: u16) -> Result<FunctionName, ParseFailure> {
    let mut parser = MsvcParser::new(raw.as_bytes(), flags)?;
    parser.parse_symbol()
}

impl<'a> MsvcParser<'a> {
    fn new(input: &'a [u8], flags: u16) -> Result<Self, ParseFailure> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(ParseFailure::InputLimitExceeded {
                attempted: input.len(),
                limit: MAX_INPUT_BYTES,
            });
        }
        let flags = if flags & UNDNAME_NAME_ONLY != 0 {
            flags
                | UNDNAME_NO_FUNCTION_RETURNS
                | UNDNAME_NO_ACCESS_SPECIFIERS
                | UNDNAME_NO_MEMBER_TYPE
                | UNDNAME_NO_ALLOCATION_LANGUAGE
                | UNDNAME_NO_COMPLEX_TYPE
        } else {
            flags
        };
        Ok(Self {
            cursor: Cursor::new(input),
            flags,
            names: RefArray::new(),
            stack: RefArray::new(),
            budget: AttemptBudget::new(),
            depth: 0,
            name_pos: 0,
        })
    }

    fn parse_top_level_frame<F>(
        &mut self,
        reject_no_arguments: bool,
        parse: F,
    ) -> Result<FunctionName, ParseFailure>
    where
        F: FnOnce(&mut Self) -> Result<FunctionName, ParseFailure>,
    {
        if reject_no_arguments && self.flags & UNDNAME_NO_ARGUMENTS != 0 {
            return Err(ParseFailure::UnsupportedNoArguments {
                offset: self.cursor.position(),
            });
        }
        if self.stack.logical_num() != 0 {
            return Err(ParseFailure::NonEmptyTopLevelStack {
                num: self.stack.logical_num(),
            });
        }

        let checkpoint = self.stack.logical_num();
        let parsed = parse(self);
        match self.stack.restore_num(checkpoint) {
            Ok(()) => parsed,
            Err(restore_error) => Err(restore_error),
        }
    }

    fn parse_symbol(&mut self) -> Result<FunctionName, ParseFailure> {
        self.parse_top_level_frame(true, Self::parse_symbol_inner)
    }

    fn parse_symbol_inner(&mut self) -> Result<FunctionName, ParseFailure> {
        let prefix_offset = self.cursor.position();
        if self.cursor.peek(0) != Some(b'?') {
            return Err(ParseFailure::InvalidMsvcPrefix {
                offset: prefix_offset,
                found: self.cursor.peek(0),
            });
        }

        if self.cursor.peek(1) == Some(b'$') {
            self.cursor.advance(2)?;
            let name = self.parse_template_name()?;
            return FunctionName::new(name, self.name_pos)
                .map_err(ParseFailure::FunctionNameValidation);
        }

        let is_operator = self.cursor.peek(1) == Some(b'?')
            && (self.cursor.peek(2) != Some(b'$') || self.cursor.peek(3) == Some(b'?'));
        if is_operator {
            return self.parse_operator_method_inner();
        }

        let is_function_template = self.cursor.peek(1) == Some(b'?')
            && self.cursor.peek(2) == Some(b'$')
            && self.cursor.peek(3) != Some(b'?');
        if is_function_template {
            self.cursor.advance(1)?;
            self.collect_class_components(0)?;
            self.names.increment_start()?;
        } else {
            self.collect_ordinary_symbol_name()?;
        }
        match self.cursor.peek(0) {
            Some(b'0'..=b'9') => self.parse_data_signature(),
            Some(b'A'..=b'Z') => self.parse_method_signature(false, false),
            Some(b'$') if self.is_supported_thunk_signature() => {
                self.parse_method_signature(false, false)
            }
            Some(found) => Err(ParseFailure::UnsupportedMethodEncoding {
                offset: self.cursor.position(),
                found,
            }),
            None => Err(ParseFailure::UnexpectedEnd {
                offset: self.cursor.position(),
            }),
        }
    }

    fn is_supported_thunk_signature(&self) -> bool {
        matches!(self.cursor.peek(1), Some(b'B' | b'R' | b'0'..=b'5'))
    }

    #[cfg(test)]
    fn parse_ordinary_data(&mut self) -> Result<FunctionName, ParseFailure> {
        self.parse_top_level_frame(false, Self::parse_ordinary_data_inner)
    }

    #[cfg(test)]
    fn parse_ordinary_data_inner(&mut self) -> Result<FunctionName, ParseFailure> {
        self.collect_ordinary_symbol_name()?;
        self.parse_data_signature()
    }

    #[cfg(test)]
    fn parse_ordinary_method(&mut self) -> Result<FunctionName, ParseFailure> {
        self.parse_top_level_frame(true, Self::parse_ordinary_method_inner)
    }

    #[cfg(test)]
    fn parse_operator_method(&mut self) -> Result<FunctionName, ParseFailure> {
        self.parse_top_level_frame(true, Self::parse_operator_method_inner)
    }

    fn parse_operator_method_inner(&mut self) -> Result<FunctionName, ParseFailure> {
        let prefix_offset = self.cursor.position();
        if self.cursor.peek(0) != Some(b'?') {
            return Err(ParseFailure::InvalidMsvcPrefix {
                offset: prefix_offset,
                found: self.cursor.peek(0),
            });
        }
        self.cursor.advance(1)?;

        let operator_offset = self.cursor.position();
        let template = if self.cursor.peek(0) == Some(b'?')
            && self.cursor.peek(1) == Some(b'$')
            && self.cursor.peek(2) == Some(b'?')
        {
            self.cursor.advance(3)?;
            true
        } else if self.cursor.peek(0) == Some(b'?') && self.cursor.peek(1) != Some(b'$') {
            self.cursor.advance(1)?;
            false
        } else {
            return Err(ParseFailure::InvalidOperatorPrefix {
                offset: operator_offset,
                found: self.cursor.peek(0),
            });
        };

        let action = self.parse_operator_action()?;
        let base_name = action.base_name();
        let mut owned_name = match action {
            OperatorAction::Rtti(operator) => self.parse_rtti_operator_name(operator)?,
            OperatorAction::Dynamic(operator) => Some(self.parse_dynamic_operator_name(operator)?),
            _ => None,
        };
        if template {
            let mut local_parameter_types = RefArray::new();
            let parsed =
                match self.parse_arguments(Some(&mut local_parameter_types), false, b'<', b'>') {
                    Ok(arguments) => Some(arguments),
                    Err(
                        error @ (ParseFailure::InvalidReferenceRestore { .. }
                        | ParseFailure::InvalidReferenceStart { .. }),
                    ) => return Err(error),
                    Err(_) => None,
                };
            self.names.restore_num(0)?;
            if let Some(arguments) = parsed {
                owned_name = Some(
                    if let Some(current_name) = owned_name.as_deref().or(base_name) {
                        allocate_concat(&mut self.budget, &[current_name, &arguments])?
                    } else {
                        arguments
                    },
                );
            }
        }

        if let OperatorAction::ImmediateString(name) = action {
            let name = match owned_name.take() {
                Some(name) => name,
                None => self.budget.copy_string(name)?,
            };
            return FunctionName::new(name, self.name_pos)
                .map_err(ParseFailure::FunctionNameValidation);
        }

        if action.is_constructor_or_destructor() {
            self.stack.push("--null--", &mut self.budget)?;
        }
        if let Some(function_name) = owned_name.as_deref().or(base_name) {
            self.stack.push(function_name, &mut self.budget)?;
        }

        if self.cursor.peek(0) == Some(b'@') {
            self.cursor.advance(1)?;
        } else if self.cursor.peek(0) == Some(b'$') {
            return Err(ParseFailure::UnsupportedClassComponent {
                offset: self.cursor.position(),
                found: b'$',
            });
        } else {
            self.collect_class_components(self.stack.logical_num())?;
        }

        if action.is_constructor_or_destructor() {
            if self.stack.logical_num() <= 1 {
                return Err(ParseFailure::EmptyClass {
                    offset: self.cursor.position(),
                });
            }
            let class_name = self.stack.active_absolute_reference(1)?;
            let replacement = if action == OperatorAction::Constructor {
                self.budget.copy_string(class_name)?
            } else {
                allocate_concat(&mut self.budget, &["~", class_name])?
            };
            self.stack.replace_active_owned(0, replacement)?;
        }

        match self.cursor.peek(0) {
            Some(b'0'..=b'9') => self.parse_data_signature(),
            _ => self.parse_method_signature(
                action == OperatorAction::Conversion,
                action.is_constructor_or_destructor() || action.has_no_function_return(),
            ),
        }
    }

    fn parse_operator_action(&mut self) -> Result<OperatorAction, ParseFailure> {
        let offset = self.cursor.position();
        let code = self.cursor.next()?;
        let action = match code {
            b'0' => OperatorAction::Constructor,
            b'1' => OperatorAction::Destructor,
            b'2' => OperatorAction::Simple("operator new"),
            b'3' => OperatorAction::Simple("operator delete"),
            b'4' => OperatorAction::Simple("operator="),
            b'5' => OperatorAction::Simple("operator>>"),
            b'6' => OperatorAction::Simple("operator<<"),
            b'7' => OperatorAction::Simple("operator!"),
            b'8' => OperatorAction::Simple("operator=="),
            b'9' => OperatorAction::Simple("operator!="),
            b'A' => OperatorAction::Simple("operator[]"),
            b'B' => OperatorAction::Conversion,
            b'C' => OperatorAction::Simple("operator->"),
            b'D' => OperatorAction::Simple("operator*"),
            b'E' => OperatorAction::Simple("operator++"),
            b'F' => OperatorAction::Simple("operator--"),
            b'G' => OperatorAction::Simple("operator-"),
            b'H' => OperatorAction::Simple("operator+"),
            b'I' => OperatorAction::Simple("operator&"),
            b'J' => OperatorAction::Simple("operator->*"),
            b'K' => OperatorAction::Simple("operator/"),
            b'L' => OperatorAction::Simple("operator%"),
            b'M' => OperatorAction::Simple("operator<"),
            b'N' => OperatorAction::Simple("operator<="),
            b'O' => OperatorAction::Simple("operator>"),
            b'P' => OperatorAction::Simple("operator>="),
            b'Q' => OperatorAction::Simple("operator,"),
            b'R' => OperatorAction::Simple("operator()"),
            b'S' => OperatorAction::Simple("operator~"),
            b'T' => OperatorAction::Simple("operator^"),
            b'U' => OperatorAction::Simple("operator|"),
            b'V' => OperatorAction::Simple("operator&&"),
            b'W' => OperatorAction::Simple("operator||"),
            b'X' => OperatorAction::Simple("operator*="),
            b'Y' => OperatorAction::Simple("operator+="),
            b'Z' => OperatorAction::Simple("operator-="),
            b'_' => return self.parse_secondary_operator_action(),
            found => {
                return Err(ParseFailure::UnsupportedOperatorCode { offset, found });
            }
        };
        Ok(action)
    }

    fn parse_secondary_operator_action(&mut self) -> Result<OperatorAction, ParseFailure> {
        let offset = self.cursor.position();
        let code = self.cursor.next()?;
        let action = match code {
            b'0' => OperatorAction::Simple("operator/="),
            b'1' => OperatorAction::Simple("operator%="),
            b'2' => OperatorAction::Simple("operator>>="),
            b'3' => OperatorAction::Simple("operator<<="),
            b'4' => OperatorAction::Simple("operator&="),
            b'5' => OperatorAction::Simple("operator|="),
            b'6' => OperatorAction::Simple("operator^="),
            b'7' => OperatorAction::Simple("`vftable'"),
            b'8' => OperatorAction::Simple("`vbtable'"),
            b'9' => OperatorAction::Simple("`vcall'"),
            b'A' => OperatorAction::Simple("`typeof'"),
            b'B' => OperatorAction::Simple("`local static guard'"),
            b'C' => OperatorAction::ImmediateString("`string'"),
            b'D' => OperatorAction::Simple("`vbase destructor'"),
            b'E' => OperatorAction::Simple("`vector deleting destructor'"),
            b'F' => OperatorAction::Simple("`default constructor closure'"),
            b'G' => OperatorAction::Simple("`scalar deleting destructor'"),
            b'H' => OperatorAction::Simple("`vector constructor iterator'"),
            b'I' => OperatorAction::Simple("`vector destructor iterator'"),
            b'J' => OperatorAction::Simple("`vector vbase constructor iterator'"),
            b'K' => OperatorAction::Simple("`virtual displacement map'"),
            b'L' => OperatorAction::Simple("`eh vector constructor iterator'"),
            b'M' => OperatorAction::Simple("`eh vector destructor iterator'"),
            b'N' => OperatorAction::Simple("`eh vector vbase constructor iterator'"),
            b'O' => OperatorAction::Simple("`copy constructor closure'"),
            b'S' => OperatorAction::Simple("`local vftable'"),
            b'T' => OperatorAction::Simple("`local vftable constructor closure'"),
            b'U' => OperatorAction::Simple("operator new[]"),
            b'V' => OperatorAction::Simple("operator delete[]"),
            b'X' => OperatorAction::Simple("`placement delete closure'"),
            b'Y' => OperatorAction::Simple("`placement delete[] closure'"),
            b'_' => return self.parse_tertiary_operator_action(),
            b'R' => return self.parse_rtti_operator_action(),
            found => {
                return Err(ParseFailure::UnsupportedOperatorCode { offset, found });
            }
        };
        Ok(action)
    }

    fn parse_rtti_operator_action(&mut self) -> Result<OperatorAction, ParseFailure> {
        let offset = self.cursor.position();
        let subtype = self.cursor.next()?;
        let operator = match subtype {
            b'0' => RttiOperator::TypeDescriptor,
            b'1' => RttiOperator::BaseClassDescriptor,
            b'2' => RttiOperator::BaseClassArray,
            b'3' => RttiOperator::ClassHierarchyDescriptor,
            b'4' => RttiOperator::CompleteObjectLocator,
            found => return Err(ParseFailure::UnsupportedOperatorCode { offset, found }),
        };
        Ok(OperatorAction::Rtti(operator))
    }

    fn parse_rtti_operator_name(
        &mut self,
        operator: RttiOperator,
    ) -> Result<Option<String>, ParseFailure> {
        match operator {
            RttiOperator::TypeDescriptor => {
                let checkpoint = self.stack.logical_num();
                let mut parameter_types = RefArray::new();
                let parsed = self.parse_datatype(Some(&mut parameter_types), false);
                let restore_result = self.stack.restore_num(checkpoint);
                let datatype = match restore_result {
                    Ok(()) => parsed?,
                    Err(error) => return Err(error),
                };
                let right = datatype.right.as_deref().map_or("", |value| value);
                Ok(Some(allocate_concat(
                    &mut self.budget,
                    &[&datatype.left, right, " `RTTI Type Descriptor'"],
                )?))
            }
            RttiOperator::BaseClassDescriptor => {
                let n1 = parse_number(&mut self.cursor, &mut self.budget)?;
                let n2 = parse_number(&mut self.cursor, &mut self.budget)?;
                let n3 = parse_number(&mut self.cursor, &mut self.budget)?;
                let n4 = parse_number(&mut self.cursor, &mut self.budget)?;
                Ok(Some(allocate_concat(
                    &mut self.budget,
                    &[
                        "`RTTI Base Class Descriptor at (",
                        &n1,
                        ",",
                        &n2,
                        ",",
                        &n3,
                        ",",
                        &n4,
                        ")'",
                    ],
                )?))
            }
            RttiOperator::BaseClassArray
            | RttiOperator::ClassHierarchyDescriptor
            | RttiOperator::CompleteObjectLocator => Ok(None),
        }
    }

    fn parse_tertiary_operator_action(&mut self) -> Result<OperatorAction, ParseFailure> {
        let offset = self.cursor.position();
        let code = self.cursor.next()?;
        let action = match code {
            b'A' => OperatorAction::Simple("`managed vector constructor iterator'"),
            b'B' => OperatorAction::Simple("`managed vector destructor iterator'"),
            b'C' => OperatorAction::Simple("`eh vector copy constructor iterator'"),
            b'D' => OperatorAction::Simple("`eh vector vbase copy constructor iterator'"),
            b'E' => OperatorAction::Dynamic(DynamicOperator::Initializer),
            b'F' => OperatorAction::Dynamic(DynamicOperator::AtexitDestructor),
            b'G' => OperatorAction::Simple("`vector copy constructor iterator'"),
            found => {
                return Err(ParseFailure::UnsupportedOperatorCode { offset, found });
            }
        };
        Ok(action)
    }

    fn parse_dynamic_operator_name(
        &mut self,
        operator: DynamicOperator,
    ) -> Result<String, ParseFailure> {
        let prefix = match operator {
            DynamicOperator::Initializer => "`dynamic initializer for '",
            DynamicOperator::AtexitDestructor => "`dynamic atexit destructor for '",
        };
        if self.cursor.peek(0) == Some(b'?') {
            let nested = self.parse_nested_symbol()?;
            self.cursor.advance(1)?;
            allocate_concat(&mut self.budget, &[prefix, nested.full_name(), "''"])
        } else {
            let literal =
                parse_literal_string(&mut self.cursor, &mut self.names, &mut self.budget)?;
            allocate_concat(&mut self.budget, &[prefix, &literal, "''"])
        }
    }

    fn collect_ordinary_symbol_name(&mut self) -> Result<(), ParseFailure> {
        let prefix_offset = self.cursor.position();
        if self.cursor.peek(0) != Some(b'?') {
            return Err(ParseFailure::InvalidMsvcPrefix {
                offset: prefix_offset,
                found: self.cursor.peek(0),
            });
        }
        self.cursor.advance(1)?;
        if let Some(found @ (b'?' | b'$')) = self.cursor.peek(0) {
            return Err(ParseFailure::UnsupportedTopLevelName {
                offset: self.cursor.position(),
                found,
            });
        }

        self.collect_class_components(0)
    }

    #[cfg(test)]
    fn parse_ordinary_method_inner(&mut self) -> Result<FunctionName, ParseFailure> {
        self.collect_ordinary_symbol_name()?;
        self.parse_method_signature(false, false)
    }

    fn parse_data_signature(&mut self) -> Result<FunctionName, ParseFailure> {
        let code_offset = self.cursor.position();
        let code = match self.cursor.peek(0) {
            Some(found @ b'0'..=b'9') => found,
            Some(found) => {
                return Err(ParseFailure::UnsupportedMethodEncoding {
                    offset: code_offset,
                    found,
                });
            }
            None => {
                return Err(ParseFailure::UnexpectedEnd {
                    offset: code_offset,
                })
            }
        };

        let access = if self.flags & UNDNAME_NO_ACCESS_SPECIFIERS != 0 {
            ""
        } else {
            match code {
                b'0' => "private: ",
                b'1' => "protected: ",
                b'2' => "public: ",
                _ => "",
            }
        };
        let member_type = if self.flags & UNDNAME_NO_MEMBER_TYPE == 0 && matches!(code, b'0'..=b'2')
        {
            "static "
        } else {
            ""
        };
        let name = render_class_name(&self.stack, 0, &mut self.budget)?;
        self.cursor.advance(1)?;

        let mut datatype = Datatype {
            left: String::new(),
            right: None,
        };
        let mut static_modifier = None;
        let mut owned_modifier = None;
        match code {
            b'0'..=b'5' => {
                let checkpoint = self.stack.logical_num();
                let mut parameter_types = RefArray::new();
                let parsed = (|| {
                    let datatype = self.parse_datatype(Some(&mut parameter_types), false)?;
                    let modifier = parse_modifier(&mut self.cursor, self.flags)?;
                    Ok((datatype, modifier))
                })();
                let restore_result = self.stack.restore_num(checkpoint);
                let (parsed_datatype, parsed_modifier) = match restore_result {
                    Ok(()) => parsed?,
                    Err(error) => return Err(error),
                };
                datatype = parsed_datatype;
                match (parsed_modifier.qualifier, parsed_modifier.pointer_modifier) {
                    (Some(qualifier), Some(pointer_modifier)) => {
                        owned_modifier = Some(allocate_concat(
                            &mut self.budget,
                            &[qualifier, " ", pointer_modifier],
                        )?);
                    }
                    (None, pointer_modifier) => static_modifier = pointer_modifier,
                    (qualifier, None) => static_modifier = qualifier,
                }
            }
            b'6' | b'7' => {
                let parsed_modifier = parse_modifier(&mut self.cursor, self.flags)?;
                static_modifier = parsed_modifier.qualifier;
                if self.cursor.peek(0) != Some(b'@') {
                    let class = self.parse_class_name()?;
                    datatype.right = Some(allocate_concat(
                        &mut self.budget,
                        &["{for `", &class, "'}"],
                    )?);
                }
            }
            b'8' | b'9' => {}
            _ => {}
        }

        if self.flags & UNDNAME_NAME_ONLY != 0 {
            datatype.left.clear();
            datatype.right = None;
            static_modifier = None;
            owned_modifier = None;
        }
        let modifier = owned_modifier.as_deref().or(static_modifier).unwrap_or("");
        let right = datatype.right.as_deref().unwrap_or("");
        let rendered = allocate_concat(
            &mut self.budget,
            &[
                access,
                member_type,
                &datatype.left,
                if !modifier.is_empty() && !datatype.left.is_empty() {
                    " "
                } else {
                    ""
                },
                modifier,
                if !modifier.is_empty() || !datatype.left.is_empty() {
                    " "
                } else {
                    ""
                },
                &name,
                right,
            ],
        )?;
        FunctionName::new(rendered, self.name_pos).map_err(ParseFailure::FunctionNameValidation)
    }

    fn parse_method_signature(
        &mut self,
        cast_operator: bool,
        no_return: bool,
    ) -> Result<FunctionName, ParseFailure> {
        let kind = self.parse_method_kind()?;
        let base_access = if self.flags & UNDNAME_NO_ACCESS_SPECIFIERS != 0 {
            ""
        } else {
            kind.access
        };
        let member_type = if self.flags & UNDNAME_NO_MEMBER_TYPE != 0 {
            ""
        } else {
            kind.member_type
        };
        let mut name = render_class_name(&self.stack, 0, &mut self.budget)?;
        let thunk_access = if kind.thunk.is_some() {
            Some(allocate_concat(
                &mut self.budget,
                &["[thunk]:", base_access],
            )?)
        } else {
            None
        };
        let access = thunk_access.as_deref().map_or(base_access, |value| value);
        if let Some(thunk) = kind.thunk {
            name = self.parse_thunk_name(name, thunk)?;
        }

        let mut modifier = None;
        if kind.has_this {
            let parsed_modifier = parse_modifier(&mut self.cursor, self.flags)?;
            if self.flags & UNDNAME_NO_THISTYPE == 0
                && (parsed_modifier.qualifier.is_some()
                    || parsed_modifier.pointer_modifier.is_some())
            {
                modifier = Some(allocate_concat(
                    &mut self.budget,
                    &[
                        parsed_modifier.qualifier.map_or("", |value| value),
                        " ",
                        parsed_modifier.pointer_modifier.map_or("", |value| value),
                    ],
                )?);
            }
        }

        let calling_convention_byte = self.cursor.next()?;
        let calling_convention = decode_calling_convention(calling_convention_byte, self.flags)?;
        let mut parameter_types = RefArray::new();
        let mut return_type = if kind.has_return {
            if self.cursor.peek(0) == Some(b'@') {
                self.cursor.advance(1)?;
                Datatype {
                    left: self.budget.copy_string("void")?,
                    right: None,
                }
            } else {
                self.parse_datatype(Some(&mut parameter_types), false)?
            }
        } else {
            Datatype {
                left: String::new(),
                right: None,
            }
        };
        if cast_operator {
            name = allocate_concat(
                &mut self.budget,
                &[
                    &name,
                    &return_type.left,
                    return_type.right.as_deref().map_or("", |value| value),
                ],
            )?;
            return_type.left.clear();
            return_type.right = None;
        } else if self.flags & UNDNAME_NO_FUNCTION_RETURNS != 0 || no_return {
            return_type.left.clear();
            return_type.right = None;
        }

        let mut arguments = if kind.has_arguments {
            let stack_checkpoint = self.stack.logical_num();
            let parsed_arguments =
                self.parse_arguments(Some(&mut parameter_types), true, b'(', b')');
            let restore_result = self.stack.restore_num(stack_checkpoint);
            match restore_result {
                Ok(()) => parsed_arguments?,
                Err(error) => return Err(error),
            }
        } else {
            String::new()
        };
        if kind.has_arguments && self.flags & UNDNAME_NAME_ONLY != 0 {
            arguments.clear();
            modifier = None;
        }

        let return_right = return_type.right.as_deref().map_or("", |value| value);
        let modifier = modifier.as_deref().map_or("", |value| value);
        let rendered = allocate_concat(
            &mut self.budget,
            &[
                access,
                member_type,
                &return_type.left,
                if !return_type.left.is_empty() && return_type.right.is_none() {
                    " "
                } else {
                    ""
                },
                calling_convention
                    .calling_convention
                    .map_or("", |value| value),
                if calling_convention.calling_convention.is_some() {
                    " "
                } else {
                    ""
                },
                calling_convention.exported.map_or("", |value| value),
                &name,
                &arguments,
                modifier,
                return_right,
            ],
        )?;
        let selector_len = name
            .len()
            .checked_add(arguments.len())
            .and_then(|value| value.checked_add(modifier.len()))
            .and_then(|value| value.checked_add(return_right.len()))
            .ok_or(ParseFailure::OutputLimitExceeded {
                attempted: usize::MAX,
                limit: MAX_OUTPUT_BYTES,
            })?;
        let selector_start = rendered.len().checked_sub(selector_len).ok_or(
            ParseFailure::FunctionNameValidation(FunctionNameError::SelectorOutOfBounds {
                selector_start: selector_len,
                len: rendered.len(),
            }),
        )?;
        self.name_pos = selector_start;
        FunctionName::new(rendered, self.name_pos).map_err(ParseFailure::FunctionNameValidation)
    }

    fn parse_method_kind(&mut self) -> Result<MethodKind, ParseFailure> {
        let offset = self.cursor.position();
        let code = self.cursor.next()?;
        match code {
            b'A'..=b'Z' => Ok(MethodKind::decode(code)),
            b'$' => self.parse_extended_method_kind(),
            found => Err(ParseFailure::UnsupportedMethodEncoding { offset, found }),
        }
    }

    fn parse_extended_method_kind(&mut self) -> Result<MethodKind, ParseFailure> {
        let offset = self.cursor.position();
        match self.cursor.next()? {
            b'B' => Ok(MethodKind::thunk("", ThunkKind::Vcall)),
            b'R' => {
                let subtype_offset = self.cursor.position();
                let subtype = self.cursor.next()?;
                let access =
                    thunk_access(subtype).ok_or(ParseFailure::UnsupportedMethodEncoding {
                        offset: subtype_offset,
                        found: subtype,
                    })?;
                Ok(MethodKind::thunk(access, ThunkKind::Vtordispex))
            }
            subtype @ b'0'..=b'5' => {
                let access =
                    thunk_access(subtype).ok_or(ParseFailure::UnsupportedMethodEncoding {
                        offset,
                        found: subtype,
                    })?;
                Ok(MethodKind::thunk(access, ThunkKind::Vtordisp))
            }
            found => Err(ParseFailure::UnsupportedMethodEncoding { offset, found }),
        }
    }

    fn parse_thunk_name(&mut self, name: String, thunk: ThunkKind) -> Result<String, ParseFailure> {
        match thunk {
            ThunkKind::Adjustor => {
                let number = parse_number(&mut self.cursor, &mut self.budget)?;
                allocate_concat(&mut self.budget, &[&name, "`adjustor{", &number, "}' "])
            }
            ThunkKind::Vtordisp => {
                let first = parse_number(&mut self.cursor, &mut self.budget)?;
                let second = parse_number(&mut self.cursor, &mut self.budget)?;
                allocate_concat(
                    &mut self.budget,
                    &[&name, "`vtordisp{", &first, ",", &second, "}' "],
                )
            }
            ThunkKind::Vtordispex => {
                let first = parse_number(&mut self.cursor, &mut self.budget)?;
                let second = parse_number(&mut self.cursor, &mut self.budget)?;
                let third = parse_number(&mut self.cursor, &mut self.budget)?;
                let fourth = parse_number(&mut self.cursor, &mut self.budget)?;
                allocate_concat(
                    &mut self.budget,
                    &[
                        &name,
                        "`vtordispex{",
                        &first,
                        ",",
                        &second,
                        ",",
                        &third,
                        ",",
                        &fourth,
                        "}' ",
                    ],
                )
            }
            ThunkKind::Vcall => {
                let number = parse_number(&mut self.cursor, &mut self.budget)?;
                let flat_offset = self.cursor.position();
                let flat = self.cursor.next()?;
                if flat != b'A' {
                    return Err(ParseFailure::UnsupportedMethodEncoding {
                        offset: flat_offset,
                        found: flat,
                    });
                }
                allocate_concat(&mut self.budget, &[&name, "{", &number, "{flat}}' "])
            }
        }
    }

    fn parse_datatype(
        &mut self,
        parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let attempted = self
            .depth
            .checked_add(1)
            .ok_or(ParseFailure::NestingLimitExceeded {
                attempted: usize::MAX,
                limit: MAX_NESTING_DEPTH,
            })?;
        if attempted > MAX_NESTING_DEPTH {
            return Err(ParseFailure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH,
            });
        }

        let previous_depth = self.depth;
        self.depth = attempted;
        let result = self.parse_datatype_inner(parameter_types, in_args);
        self.depth = previous_depth;
        result
    }

    fn parse_arguments(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        z_terminated: bool,
        open: u8,
        close: u8,
    ) -> Result<String, ParseFailure> {
        if !open.is_ascii() || !close.is_ascii() {
            return Err(ParseFailure::InvalidArgumentDelimiter { open, close });
        }
        let mut arguments: Vec<String> = Vec::new();

        while self.cursor.peek(0).is_some() {
            if self.cursor.peek(0) == Some(b'@') {
                self.cursor.advance(1)?;
                break;
            }
            if close == b'>'
                && self.cursor.peek(0) == Some(b'$')
                && self.cursor.peek(1) == Some(b'$')
                && matches!(self.cursor.peek(2), Some(b'V' | b'Z'))
            {
                self.cursor.advance(3)?;
                continue;
            }

            let attempted =
                arguments
                    .len()
                    .checked_add(1)
                    .ok_or(ParseFailure::ArgumentLimitExceeded {
                        attempted: usize::MAX,
                        limit: MAX_ARGUMENTS,
                    })?;
            if attempted > MAX_ARGUMENTS {
                return Err(ParseFailure::ArgumentLimitExceeded {
                    attempted,
                    limit: MAX_ARGUMENTS,
                });
            }
            arguments
                .try_reserve(1)
                .map_err(|_| ParseFailure::ArgumentCollectionAllocationFailed { additional: 1 })?;

            let datatype = self.parse_datatype(parameter_types.as_deref_mut(), true)?;
            if z_terminated && datatype.left == "void" {
                break;
            }
            let right = datatype.right.as_deref().map_or("", |right| right);
            let argument = allocate_concat(&mut self.budget, &[&datatype.left, right])?;
            let variadic = datatype.left == "...";
            arguments.push(argument);
            if variadic {
                break;
            }
        }

        if z_terminated {
            let offset = self.cursor.position();
            let found = self.cursor.next()?;
            if found != b'Z' {
                return Err(ParseFailure::InvalidArgumentListTerminator { offset, found });
            }
        }

        self.render_arguments(&arguments, open, close)
    }

    fn render_arguments(
        &mut self,
        arguments: &[String],
        open: u8,
        close: u8,
    ) -> Result<String, ParseFailure> {
        let render_void = arguments.is_empty()
            || (arguments.len() == 1 && arguments.first().map(String::as_str) == Some("void"));
        let nested_closing = close == b'>'
            && arguments
                .last()
                .map(String::as_str)
                .is_some_and(|argument| argument.ends_with('>'));
        let open = char::from(open);
        let close = char::from(close);
        let mut output_len = open.len_utf8().checked_add(close.len_utf8()).ok_or(
            ParseFailure::OutputLimitExceeded {
                attempted: usize::MAX,
                limit: MAX_OUTPUT_BYTES,
            },
        )?;
        if render_void {
            output_len = output_len
                .checked_add(4)
                .ok_or(ParseFailure::OutputLimitExceeded {
                    attempted: usize::MAX,
                    limit: MAX_OUTPUT_BYTES,
                })?;
        } else {
            for (index, argument) in arguments.iter().enumerate() {
                output_len = output_len.checked_add(argument.len()).ok_or(
                    ParseFailure::OutputLimitExceeded {
                        attempted: usize::MAX,
                        limit: MAX_OUTPUT_BYTES,
                    },
                )?;
                if index != 0 {
                    output_len =
                        output_len
                            .checked_add(1)
                            .ok_or(ParseFailure::OutputLimitExceeded {
                                attempted: usize::MAX,
                                limit: MAX_OUTPUT_BYTES,
                            })?;
                }
            }
            if nested_closing {
                output_len =
                    output_len
                        .checked_add(1)
                        .ok_or(ParseFailure::OutputLimitExceeded {
                            attempted: usize::MAX,
                            limit: MAX_OUTPUT_BYTES,
                        })?;
            }
        }

        let reservation = self.budget.preflight(output_len)?;
        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| ParseFailure::OutputAllocationFailed {
                additional: output_len,
            })?;
        output.push(open);
        if render_void {
            output.push_str("void");
        } else {
            for (index, argument) in arguments.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(argument);
            }
            if nested_closing {
                output.push(' ');
            }
        }
        output.push(close);
        self.budget.commit(reservation);
        Ok(output)
    }

    fn parse_datatype_inner(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let code = self.cursor.peek(0);
        if code == Some(b'$') && self.cursor.peek(1) == Some(b'1') {
            self.cursor.advance(2)?;
            return self.parse_recursive_symbol_type(parameter_types, in_args);
        }
        if code == Some(b'$') && self.cursor.peek(1) == Some(b'$') {
            match self.cursor.peek(2) {
                Some(b'A') => {
                    self.cursor.advance(3)?;
                    let offset = self.cursor.position();
                    match self.cursor.peek(0) {
                        Some(b'6') => {
                            self.cursor.advance(1)?;
                            return self.parse_standalone_function_type(parameter_types, in_args);
                        }
                        Some(found) => {
                            return Err(ParseFailure::UnsupportedDatatypeForm {
                                offset,
                                found,
                                introducer: "$$A",
                            });
                        }
                        None => return Err(ParseFailure::UnexpectedEnd { offset }),
                    }
                }
                Some(b'B') => {
                    self.cursor.advance(3)?;
                    return self.parse_recursive_array_type(parameter_types, in_args);
                }
                Some(b'C') => {
                    self.cursor.advance(3)?;
                    return self.parse_recursive_qualified_type(parameter_types, in_args);
                }
                Some(b'Q') => {
                    self.cursor.advance(3)?;
                    return self.parse_modified_type(
                        parameter_types,
                        b'?',
                        in_args,
                        true,
                        Some(" &&"),
                    );
                }
                _ => {}
            }
        }
        match code {
            Some(modifier @ (b'A' | b'B')) => {
                self.cursor.advance(1)?;
                return self.parse_modified_type(parameter_types, modifier, in_args, true, None);
            }
            Some(modifier @ (b'P' | b'Q')) => {
                self.cursor.advance(1)?;
                if let Some(found @ b'0'..=b'9') = self.cursor.peek(0) {
                    let offset = self.cursor.position();
                    self.cursor.advance(1)?;
                    if found == b'6' {
                        return self.parse_function_pointer_type(
                            parameter_types,
                            modifier,
                            in_args,
                        );
                    }
                    if found == b'8' && modifier == b'P' {
                        return self.parse_member_function_pointer_type(parameter_types, in_args);
                    }
                    return Err(ParseFailure::UnsupportedDatatypeForm {
                        offset,
                        found,
                        introducer: if modifier == b'P' { "P" } else { "Q" },
                    });
                }
                let modifier = if modifier == b'Q' && !in_args {
                    b'P'
                } else {
                    modifier
                };
                return self.parse_modified_type(parameter_types, modifier, in_args, true, None);
            }
            Some(modifier @ (b'R' | b'S')) => {
                self.cursor.advance(1)?;
                let modifier = if in_args { modifier } else { b'P' };
                return self.parse_modified_type(parameter_types, modifier, in_args, true, None);
            }
            Some(b'?') => {
                self.cursor.advance(1)?;
                if !in_args {
                    return self.parse_modified_type(parameter_types, b'?', in_args, true, None);
                }
                let number = parse_number(&mut self.cursor, &mut self.budget)?;
                let left =
                    allocate_concat(&mut self.budget, &["`template-parameter-", &number, "'"])?;
                let datatype = Datatype { left, right: None };
                if let Some(parameter_types) = parameter_types {
                    parameter_types.push_pair(&datatype.left, "", &mut self.budget)?;
                }
                return Ok(datatype);
            }
            _ => {}
        }

        let prefix = match code {
            Some(b'T') => "union ",
            Some(b'U') => "struct ",
            Some(b'V') => "class ",
            Some(b'Y') => "cointerface ",
            Some(b'W') => {
                self.cursor.advance(1)?;
                match self.cursor.peek(0) {
                    Some(b'4') => self.cursor.advance(1)?,
                    Some(found) => {
                        return Err(ParseFailure::UnsupportedDatatypeForm {
                            offset: self.cursor.position(),
                            found,
                            introducer: "W",
                        });
                    }
                    None => {
                        return Err(ParseFailure::UnexpectedEnd {
                            offset: self.cursor.position(),
                        });
                    }
                }
                return self.parse_named_datatype("enum ", parameter_types, in_args);
            }
            _ => {
                return parse_datatype(
                    &mut self.cursor,
                    parameter_types.as_deref_mut(),
                    in_args,
                    &mut self.budget,
                );
            }
        };
        self.cursor.advance(1)?;
        self.parse_named_datatype(prefix, parameter_types, in_args)
    }

    fn parse_recursive_symbol_type(
        &mut self,
        parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let nested = self.parse_nested_symbol()?;
        let datatype = Datatype {
            left: allocate_concat(&mut self.budget, &["&", nested.full_name()])?,
            right: None,
        };
        self.record_outer_parameter_type(parameter_types, in_args, &datatype)?;
        Ok(datatype)
    }

    fn parse_standalone_function_type(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let checkpoint = self.stack.logical_num();
        let parsed = self.parse_standalone_function_type_body(parameter_types.as_deref_mut());
        match self.stack.restore_num(checkpoint) {
            Ok(()) => {}
            Err(restore_error) => return Err(restore_error),
        }
        let datatype = self.render_standalone_function_type(parsed?)?;
        self.record_outer_parameter_type(parameter_types, in_args, &datatype)?;
        Ok(datatype)
    }

    fn parse_standalone_function_type_body(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
    ) -> Result<StandaloneFunctionParts, ParseFailure> {
        let calling_convention_byte = self.cursor.next()?;
        let calling_convention = decode_calling_convention(
            calling_convention_byte,
            self.flags & !UNDNAME_NO_ALLOCATION_LANGUAGE,
        )?;
        let return_type = self.parse_datatype(parameter_types.as_deref_mut(), false)?;
        let arguments = self.parse_arguments(parameter_types, true, b'(', b')')?;
        Ok(StandaloneFunctionParts {
            calling_convention: calling_convention.calling_convention,
            exported: calling_convention.exported,
            return_type,
            arguments,
        })
    }

    fn render_standalone_function_type(
        &mut self,
        parsed: StandaloneFunctionParts,
    ) -> Result<Datatype, ParseFailure> {
        let StandaloneFunctionParts {
            calling_convention,
            exported,
            return_type,
            arguments,
        } = parsed;
        let return_right = return_type.right.as_deref().map_or("", |right| right);
        let left = allocate_concat(
            &mut self.budget,
            &[
                &return_type.left,
                if return_type.right.is_none() { " " } else { "" },
                calling_convention.map_or("", |value| value),
                if calling_convention.is_some() {
                    " "
                } else {
                    ""
                },
                exported.map_or("", |value| value),
                &arguments,
                return_right,
            ],
        )?;
        Ok(Datatype { left, right: None })
    }

    fn parse_function_pointer_type(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        modifier: u8,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let checkpoint = self.stack.logical_num();
        let result = self
            .parse_function_pointer_type_inner(parameter_types.as_deref_mut(), modifier == b'Q');
        let result = match result {
            Ok(datatype) => {
                match self.record_outer_parameter_type(parameter_types, in_args, &datatype) {
                    Ok(()) => Ok(datatype),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        match self.stack.restore_num(checkpoint) {
            Ok(()) => result,
            Err(restore_error) => Err(restore_error),
        }
    }

    fn parse_function_pointer_type_inner(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        is_const: bool,
    ) -> Result<Datatype, ParseFailure> {
        let calling_convention_byte = self.cursor.next()?;
        let calling_convention = decode_calling_convention(
            calling_convention_byte,
            self.flags & !UNDNAME_NO_ALLOCATION_LANGUAGE,
        )?;
        let return_type = self.parse_datatype(parameter_types.as_deref_mut(), false)?;
        let arguments = self.parse_arguments(parameter_types, true, b'(', b')')?;
        let return_right = return_type.right.as_deref().map_or("", |right| right);
        let calling_convention = calling_convention
            .calling_convention
            .map_or("", |calling_convention| calling_convention);
        let pointer = if is_const { "*const" } else { "*" };
        let left = allocate_concat(
            &mut self.budget,
            &[
                &return_type.left,
                return_right,
                " (",
                calling_convention,
                pointer,
            ],
        )?;
        let right = allocate_concat(&mut self.budget, &[")", &arguments])?;
        Ok(Datatype {
            left,
            right: Some(right),
        })
    }

    fn parse_member_function_pointer_type(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let checkpoint = self.stack.logical_num();
        let parsed = self.parse_member_function_pointer_type_body(parameter_types.as_deref_mut());
        match self.stack.restore_num(checkpoint) {
            Ok(()) => {}
            Err(restore_error) => return Err(restore_error),
        }
        let datatype = self.render_member_function_pointer_type(parsed?)?;
        self.record_outer_parameter_type(parameter_types, in_args, &datatype)?;
        Ok(datatype)
    }

    fn parse_member_function_pointer_type_body(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
    ) -> Result<MemberFunctionPointerParts, ParseFailure> {
        let class = self.parse_class_name()?;
        let parsed_modifier = parse_modifier(&mut self.cursor, self.flags)?;
        let post_modifier = match (parsed_modifier.qualifier, parsed_modifier.pointer_modifier) {
            (Some(qualifier), Some(pointer_modifier)) => Some(MemberFunctionModifier::Owned(
                allocate_concat(&mut self.budget, &[qualifier, " ", pointer_modifier])?,
            )),
            (Some(qualifier), None) => Some(MemberFunctionModifier::Static(qualifier)),
            (None, Some(pointer_modifier)) => {
                Some(MemberFunctionModifier::Static(pointer_modifier))
            }
            (None, None) => None,
        };
        let calling_convention_byte = self.cursor.next()?;
        let calling_convention = decode_calling_convention(
            calling_convention_byte,
            self.flags & !UNDNAME_NO_ALLOCATION_LANGUAGE,
        )?;
        let return_type = self.parse_datatype(parameter_types.as_deref_mut(), false)?;
        let arguments = self.parse_arguments(parameter_types, true, b'(', b')')?;
        Ok(MemberFunctionPointerParts {
            class,
            post_modifier,
            calling_convention: calling_convention.calling_convention,
            return_type,
            arguments,
        })
    }

    fn render_member_function_pointer_type(
        &mut self,
        parsed: MemberFunctionPointerParts,
    ) -> Result<Datatype, ParseFailure> {
        let MemberFunctionPointerParts {
            class,
            post_modifier,
            calling_convention,
            return_type,
            arguments,
        } = parsed;
        let return_right = return_type.right.as_deref().map_or("", |right| right);
        let left = allocate_concat(
            &mut self.budget,
            &[
                &return_type.left,
                return_right,
                " (",
                calling_convention.map_or("", |value| value),
                if calling_convention.is_some() {
                    " "
                } else {
                    ""
                },
                &class,
                "::*",
            ],
        )?;
        let right = match post_modifier {
            Some(modifier) => {
                allocate_concat(&mut self.budget, &[")", &arguments, " ", modifier.as_str()])?
            }
            None => allocate_concat(&mut self.budget, &[")", &arguments])?,
        };
        Ok(Datatype {
            left,
            right: Some(right),
        })
    }

    fn parse_recursive_qualified_type(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let modifier = parse_modifier(&mut self.cursor, self.flags)?;
        let subtype = self.parse_datatype(parameter_types.as_deref_mut(), in_args)?;
        let qualifier = modifier.qualifier.map_or("", |qualifier| qualifier);
        let datatype = Datatype {
            left: allocate_concat(&mut self.budget, &[&subtype.left, " ", qualifier])?,
            right: subtype.right,
        };
        self.record_outer_parameter_type(parameter_types, in_args, &datatype)?;
        Ok(datatype)
    }

    fn parse_recursive_array_type(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let suffix = self.parse_standalone_array_suffix()?;
        let subtype = self.parse_datatype(parameter_types.as_deref_mut(), in_args)?;
        let left = match suffix {
            Some(suffix) => allocate_concat(&mut self.budget, &[&subtype.left, " ", &suffix])?,
            None => allocate_concat(&mut self.budget, &[&subtype.left, " "])?,
        };
        let datatype = Datatype {
            left,
            right: subtype.right,
        };
        self.record_outer_parameter_type(parameter_types, in_args, &datatype)?;
        Ok(datatype)
    }

    fn parse_standalone_array_suffix(&mut self) -> Result<Option<String>, ParseFailure> {
        if self.cursor.peek(0) != Some(b'Y') {
            return Ok(None);
        }
        self.cursor.advance(1)?;
        let count_offset = self.cursor.position();
        let rendered_count = parse_number(&mut self.cursor, &mut self.budget)?;
        let count = parse_array_dimension_count(&rendered_count, count_offset)?;
        if count > MAX_STANDALONE_ARRAY_DIMENSIONS {
            return Err(ParseFailure::ArrayDimensionLimitExceeded {
                attempted: count,
                limit: MAX_STANDALONE_ARRAY_DIMENSIONS,
            });
        }

        let mut suffix: Option<String> = None;
        for _ in 0..count {
            let dimension = parse_number(&mut self.cursor, &mut self.budget)?;
            suffix = Some(match suffix {
                Some(current) => {
                    allocate_concat(&mut self.budget, &[&current, "[", &dimension, "]"])?
                }
                None => allocate_concat(&mut self.budget, &["[", &dimension, "]"])?,
            });
        }
        Ok(suffix)
    }

    fn record_outer_parameter_type(
        &mut self,
        parameter_types: Option<&mut RefArray>,
        in_args: bool,
        datatype: &Datatype,
    ) -> Result<(), ParseFailure> {
        if in_args {
            if let Some(parameter_types) = parameter_types {
                let right = datatype.right.as_deref().map_or("", |right| right);
                parameter_types.push_pair(&datatype.left, right, &mut self.budget)?;
            }
        }
        Ok(())
    }

    fn parse_modified_type(
        &mut self,
        mut parameter_types: Option<&mut RefArray>,
        modifier: u8,
        in_args: bool,
        record_outer_pmt: bool,
        final_suffix: Option<&'static str>,
    ) -> Result<Datatype, ParseFailure> {
        let checkpoint = self.stack.logical_num();
        let result =
            self.parse_modified_type_inner(parameter_types.as_deref_mut(), modifier, in_args);
        let result = match result {
            Ok(datatype) => self.finish_modified_type(
                datatype,
                parameter_types,
                in_args,
                record_outer_pmt,
                final_suffix,
            ),
            Err(error) => Err(error),
        };
        match self.stack.restore_num(checkpoint) {
            Ok(()) => result,
            Err(restore_error) => Err(restore_error),
        }
    }

    fn finish_modified_type(
        &mut self,
        mut datatype: Datatype,
        parameter_types: Option<&mut RefArray>,
        in_args: bool,
        record_outer_pmt: bool,
        final_suffix: Option<&'static str>,
    ) -> Result<Datatype, ParseFailure> {
        if let Some(final_suffix) = final_suffix {
            datatype.left = allocate_concat(&mut self.budget, &[&datatype.left, final_suffix])?;
        }
        if record_outer_pmt {
            self.record_outer_parameter_type(parameter_types, in_args, &datatype)?;
        }
        Ok(datatype)
    }

    fn parse_modified_type_inner(
        &mut self,
        parameter_types: Option<&mut RefArray>,
        modifier: u8,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let mut pointer_extensions = String::new();
        if self.cursor.peek(0) == Some(b'E') {
            self.cursor.advance(1)?;
            if self.flags & UNDNAME_NO_MS_KEYWORDS == 0 {
                let keyword = if self.flags & UNDNAME_NO_LEADING_UNDERSCORES != 0 {
                    "ptr64"
                } else {
                    "__ptr64"
                };
                pointer_extensions = allocate_concat(&mut self.budget, &[" ", keyword])?;
            }
        }
        if self.cursor.peek(0) == Some(b'I') {
            self.cursor.advance(1)?;
            if self.flags & UNDNAME_NO_MS_KEYWORDS == 0 {
                let keyword = if self.flags & UNDNAME_NO_LEADING_UNDERSCORES != 0 {
                    "restrict"
                } else {
                    "__restrict"
                };
                pointer_extensions =
                    allocate_concat(&mut self.budget, &[&pointer_extensions, " ", keyword])?;
            }
        }

        let mut rendered_modifier = match modifier {
            b'A' => allocate_concat(&mut self.budget, &[" &", &pointer_extensions])?,
            b'B' => allocate_concat(&mut self.budget, &[" &", &pointer_extensions, " volatile"])?,
            b'P' => allocate_concat(&mut self.budget, &[" *", &pointer_extensions])?,
            b'Q' => allocate_concat(&mut self.budget, &[" *", &pointer_extensions, " const"])?,
            b'R' => allocate_concat(&mut self.budget, &[" *", &pointer_extensions, " volatile"])?,
            b'S' => allocate_concat(
                &mut self.budget,
                &[" *", &pointer_extensions, " const volatile"],
            )?,
            b'?' => String::new(),
            found => {
                return Err(ParseFailure::UnsupportedDatatypeForm {
                    offset: self.cursor.position(),
                    found,
                    introducer: "modified type",
                });
            }
        };

        if self.cursor.peek(0) == Some(b'F') {
            self.cursor.advance(1)?;
            if self.flags & UNDNAME_NO_MS_KEYWORDS == 0 {
                let keyword = if self.flags & UNDNAME_NO_LEADING_UNDERSCORES != 0 {
                    "unaligned"
                } else {
                    "__unaligned"
                };
                rendered_modifier =
                    allocate_concat(&mut self.budget, &[" ", keyword, &rendered_modifier])?;
            }
        }

        let parsed_modifier = parse_modifier(&mut self.cursor, self.flags)?;
        let mut qualifier = parsed_modifier.qualifier;
        if self.cursor.peek(0) == Some(b'Y') {
            rendered_modifier = self.parse_modified_array(rendered_modifier, qualifier)?;
            qualifier = None;
        }

        let subtype = self.parse_datatype(parameter_types, false)?;
        let left = if let Some(qualifier) = qualifier {
            allocate_concat(
                &mut self.budget,
                &[&subtype.left, " ", qualifier, &rendered_modifier],
            )?
        } else {
            let rendered_modifier =
                if !in_args && rendered_modifier.starts_with(" *") && subtype.left.ends_with('*') {
                    match rendered_modifier.strip_prefix(' ') {
                        Some(without_space) => without_space,
                        None => rendered_modifier.as_str(),
                    }
                } else {
                    rendered_modifier.as_str()
                };
            allocate_concat(&mut self.budget, &[&subtype.left, rendered_modifier])?
        };
        Ok(Datatype {
            left,
            right: subtype.right,
        })
    }

    fn parse_modified_array(
        &mut self,
        rendered_modifier: String,
        qualifier: Option<&'static str>,
    ) -> Result<String, ParseFailure> {
        self.cursor.advance(1)?;
        let count_offset = self.cursor.position();
        let rendered_count = parse_number(&mut self.cursor, &mut self.budget)?;
        let count = parse_array_dimension_count(&rendered_count, count_offset)?.min(128);

        let without_optional_leading_space = if qualifier.is_none() {
            rendered_modifier
                .strip_prefix(' ')
                .map_or(rendered_modifier.as_str(), |modifier| modifier)
        } else {
            rendered_modifier.as_str()
        };
        let mut suffix = if let Some(array_qualifier) = qualifier {
            allocate_concat(
                &mut self.budget,
                &[" (", array_qualifier, without_optional_leading_space, ")"],
            )?
        } else {
            allocate_concat(
                &mut self.budget,
                &[" (", without_optional_leading_space, ")"],
            )?
        };

        for _ in 0..count {
            let dimension = parse_number(&mut self.cursor, &mut self.budget)?;
            suffix = allocate_concat(&mut self.budget, &[&suffix, "[", &dimension, "]"])?;
        }
        Ok(suffix)
    }

    fn parse_named_datatype(
        &mut self,
        prefix: &'static str,
        parameter_types: Option<&mut RefArray>,
        in_args: bool,
    ) -> Result<Datatype, ParseFailure> {
        let class_name = self.parse_class_name()?;
        let left = if self.flags & UNDNAME_NO_COMPLEX_TYPE != 0 {
            class_name
        } else {
            allocate_concat(&mut self.budget, &[prefix, &class_name])?
        };
        let datatype = Datatype { left, right: None };
        if in_args {
            if let Some(parameter_types) = parameter_types {
                parameter_types.push_pair(&datatype.left, "", &mut self.budget)?;
            }
        }
        Ok(datatype)
    }

    fn parse_class_name(&mut self) -> Result<String, ParseFailure> {
        let checkpoint = self.stack.logical_num();
        let result = match self.collect_class_components(checkpoint) {
            Ok(()) => render_class_name(&self.stack, checkpoint, &mut self.budget),
            Err(error) => Err(error),
        };
        match self.stack.restore_num(checkpoint) {
            Ok(()) => result,
            Err(restore_error) => Err(restore_error),
        }
    }

    fn collect_class_components(&mut self, checkpoint: usize) -> Result<(), ParseFailure> {
        let mut output_len = 0_usize;
        loop {
            let has_previous = self.stack.logical_num() != checkpoint;
            match self.cursor.peek(0) {
                Some(b'@') => {
                    let terminator_offset = self.cursor.position();
                    self.cursor.advance(1)?;
                    if self.stack.logical_num() == checkpoint {
                        return Err(ParseFailure::EmptyClass {
                            offset: terminator_offset,
                        });
                    }
                    return Ok(());
                }
                None => {
                    return Err(ParseFailure::UnexpectedEnd {
                        offset: self.cursor.position(),
                    });
                }
                Some(b'?') => {
                    self.cursor.advance(1)?;
                    output_len = self.parse_question_class_component(output_len, has_previous)?;
                }
                Some(digit @ b'0'..=b'9') => {
                    self.cursor.advance(1)?;
                    let referenced = self.names.reference(usize::from(digit - b'0'))?;
                    let next_output_len =
                        checked_class_output_len(output_len, referenced.len(), has_previous)?;
                    self.stack.push(referenced, &mut self.budget)?;
                    output_len = next_output_len;
                }
                Some(_) => {
                    let component =
                        parse_literal_string(&mut self.cursor, &mut self.names, &mut self.budget)?;
                    let next_output_len =
                        checked_class_output_len(output_len, component.len(), has_previous)?;
                    self.stack.push(&component, &mut self.budget)?;
                    output_len = next_output_len;
                }
            }
        }
    }

    fn parse_question_class_component(
        &mut self,
        output_len: usize,
        has_previous: bool,
    ) -> Result<usize, ParseFailure> {
        let offset = self.cursor.position();
        match self.cursor.peek(0) {
            Some(b'$') => {
                self.cursor.advance(1)?;
                self.parse_template_class_component(output_len, has_previous)
            }
            Some(b'?') => self.parse_nested_symbol_class_component(output_len, has_previous),
            Some(b'A') => self.parse_anonymous_class_component(output_len, has_previous),
            Some(_) => self.parse_numeric_class_component(output_len, has_previous),
            None => Err(ParseFailure::UnexpectedEnd { offset }),
        }
    }

    fn parse_nested_symbol_class_component(
        &mut self,
        output_len: usize,
        has_previous: bool,
    ) -> Result<usize, ParseFailure> {
        let nested = self.parse_nested_symbol()?;
        let component = allocate_concat(&mut self.budget, &["`", nested.full_name(), "'"])?;
        let next_output_len = checked_class_output_len(output_len, component.len(), has_previous)?;
        self.stack.push(&component, &mut self.budget)?;
        Ok(next_output_len)
    }

    fn parse_nested_symbol(&mut self) -> Result<FunctionName, ParseFailure> {
        let names_num = self.names.logical_num();
        let names_start = self.names.logical_start();
        let outer_stack = std::mem::replace(&mut self.stack, RefArray::new());

        let attempted = self
            .depth
            .checked_add(1)
            .ok_or(ParseFailure::NestingLimitExceeded {
                attempted: usize::MAX,
                limit: MAX_NESTING_DEPTH,
            });
        let parsed = match attempted {
            Ok(attempted) if attempted <= MAX_NESTING_DEPTH => {
                let previous_depth = self.depth;
                self.depth = attempted;
                let parsed = self.parse_symbol();
                self.depth = previous_depth;
                parsed
            }
            Ok(attempted) => Err(ParseFailure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH,
            }),
            Err(error) => Err(error),
        };

        let names_num_result = self.names.restore_num(names_num);
        let names_start_result = self.names.set_start(names_start);
        let temporary_stack = std::mem::replace(&mut self.stack, outer_stack);
        drop(temporary_stack);
        names_num_result?;
        names_start_result?;
        parsed
    }

    fn parse_anonymous_class_component(
        &mut self,
        output_len: usize,
        has_previous: bool,
    ) -> Result<usize, ParseFailure> {
        parse_literal_string(&mut self.cursor, &mut self.names, &mut self.budget)?;
        self.names
            .replace_last_active("`anonymous namespace'", &mut self.budget)?;
        let index = self.names.logical_num().checked_sub(1).ok_or(
            ParseFailure::ActiveReferenceOutOfRange {
                index: 0,
                num: self.names.logical_num(),
            },
        )?;
        let component = self.names.active_absolute_reference(index)?;
        let next_output_len = checked_class_output_len(output_len, component.len(), has_previous)?;
        self.stack.push(component, &mut self.budget)?;
        Ok(next_output_len)
    }

    fn parse_numeric_class_component(
        &mut self,
        output_len: usize,
        has_previous: bool,
    ) -> Result<usize, ParseFailure> {
        let number = parse_number(&mut self.cursor, &mut self.budget)?;
        let component = allocate_concat(&mut self.budget, &["`", &number, "'"])?;
        let next_output_len = checked_class_output_len(output_len, component.len(), has_previous)?;
        self.stack.push(&component, &mut self.budget)?;
        Ok(next_output_len)
    }

    fn parse_template_class_component(
        &mut self,
        output_len: usize,
        has_previous: bool,
    ) -> Result<usize, ParseFailure> {
        let component = self.parse_template_name()?;
        let next_output_len = checked_class_output_len(output_len, component.len(), has_previous)?;
        self.names.push(&component, &mut self.budget)?;
        self.stack.push(&component, &mut self.budget)?;
        Ok(next_output_len)
    }

    fn parse_template_name(&mut self) -> Result<String, ParseFailure> {
        let names_num = self.names.logical_num();
        let names_start = self.names.logical_start();
        let stack_num = self.stack.logical_num();

        if let Err(error) = self.names.set_start(names_num) {
            self.restore_template_state(names_num, names_start, stack_num)?;
            return Err(error);
        }
        let parsed = self.parse_template_name_body();
        // The native helper leaks its scoped logical state when the literal
        // fails. Safe Rust restores it too, avoiding unusable parser state.
        self.restore_template_state(names_num, names_start, stack_num)?;
        self.render_template_name(parsed?)
    }

    fn parse_template_name_body(&mut self) -> Result<TemplateNameParts, ParseFailure> {
        let literal = parse_literal_string(&mut self.cursor, &mut self.names, &mut self.budget)?;
        let mut local_parameter_types = RefArray::new();
        let arguments =
            match self.parse_arguments(Some(&mut local_parameter_types), false, b'<', b'>') {
                Ok(arguments) => Some(arguments),
                Err(
                    error @ (ParseFailure::InvalidReferenceRestore { .. }
                    | ParseFailure::InvalidReferenceStart { .. }),
                ) => return Err(error),
                Err(_) => None,
            };
        Ok(TemplateNameParts { literal, arguments })
    }

    fn render_template_name(&mut self, parsed: TemplateNameParts) -> Result<String, ParseFailure> {
        match parsed.arguments {
            Some(arguments) => allocate_concat(&mut self.budget, &[&parsed.literal, &arguments]),
            None => Ok(parsed.literal),
        }
    }

    fn restore_template_state(
        &mut self,
        names_num: usize,
        names_start: usize,
        stack_num: usize,
    ) -> Result<(), ParseFailure> {
        let names_num_result = self.names.restore_num(names_num);
        let names_start_result = self.names.set_start(names_start);
        let stack_num_result = self.stack.restore_num(stack_num);
        names_num_result?;
        names_start_result?;
        stack_num_result
    }
}

fn thunk_access(subtype: u8) -> Option<&'static str> {
    match subtype {
        b'0' | b'1' => Some("private: "),
        b'2' | b'3' => Some("protected: "),
        b'4' | b'5' => Some("public: "),
        _ => None,
    }
}

fn parse_array_dimension_count(rendered: &str, offset: usize) -> Result<usize, ParseFailure> {
    let (negative, digits) = match rendered.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, rendered),
    };
    let magnitude = digits.bytes().try_fold(0_u32, |value, byte| {
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit <= 9)
            .ok_or(ParseFailure::InvalidArrayDimensionCount { offset })?;
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit)))
            .filter(|value| *value <= MAX_ENCODED_NUMBER)
            .ok_or(ParseFailure::InvalidArrayDimensionCount { offset })
    })?;
    if negative && magnitude != 0 {
        let value = i32::try_from(magnitude)
            .map_err(|_| ParseFailure::InvalidArrayDimensionCount { offset })?;
        return Err(ParseFailure::NegativeArrayDimensionCount {
            offset,
            value: -value,
        });
    }
    usize::try_from(magnitude).map_err(|_| ParseFailure::InvalidArrayDimensionCount { offset })
}

fn allocate_concat(budget: &mut AttemptBudget, parts: &[&str]) -> Result<String, ParseFailure> {
    let output_len = parts
        .iter()
        .try_fold(0_usize, |length, part| length.checked_add(part.len()))
        .ok_or(ParseFailure::OutputLimitExceeded {
            attempted: usize::MAX,
            limit: MAX_OUTPUT_BYTES,
        })?;
    if output_len > MAX_OUTPUT_BYTES {
        return Err(ParseFailure::OutputLimitExceeded {
            attempted: output_len,
            limit: MAX_OUTPUT_BYTES,
        });
    }

    let reservation = budget.preflight(output_len)?;
    let mut output = String::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| ParseFailure::OutputAllocationFailed {
            additional: output_len,
        })?;
    for part in parts {
        output.push_str(part);
    }
    budget.commit(reservation);
    Ok(output)
}

fn parse_datatype(
    cursor: &mut Cursor<'_>,
    parameter_types: Option<&mut RefArray>,
    in_args: bool,
    budget: &mut AttemptBudget,
) -> Result<Datatype, ParseFailure> {
    let offset = cursor.position();
    let code = cursor.next()?;

    if let Some(left) = ordinary_primitive_type(code) {
        return Ok(Datatype {
            left: budget.copy_string(left)?,
            right: None,
        });
    }

    let datatype = if code == b'_' {
        let subtype_offset = cursor.position();
        let subtype = cursor.next()?;
        let left = extended_primitive_type(subtype).ok_or(ParseFailure::InvalidDatatypeCode {
            offset: subtype_offset,
            found: subtype,
        })?;
        Datatype {
            left: budget.copy_string(left)?,
            right: None,
        }
    } else if code == b'$' {
        let subtype_offset = cursor.position();
        let subtype = cursor.next()?;
        let left = match subtype {
            b'0' => parse_number(cursor, budget)?,
            b'D' => {
                let number = parse_number(cursor, budget)?;
                allocate_concat(budget, &["`template-parameter", &number, "'"])?
            }
            b'F' => {
                let first = parse_number(cursor, budget)?;
                let second = parse_number(cursor, budget)?;
                allocate_concat(budget, &["{", &first, ",", &second, "}"])?
            }
            b'G' => {
                let first = parse_number(cursor, budget)?;
                let second = parse_number(cursor, budget)?;
                let third = parse_number(cursor, budget)?;
                allocate_concat(budget, &["{", &first, ",", &second, ",", &third, "}"])?
            }
            b'Q' => {
                let number = parse_number(cursor, budget)?;
                allocate_concat(budget, &["`non-type-template-parameter", &number, "'"])?
            }
            b'$' => match cursor.peek(0) {
                Some(b'T') => {
                    cursor.advance(1)?;
                    budget.copy_string("std::nullptr_t")?
                }
                Some(found) => {
                    return Err(ParseFailure::UnsupportedDatatypeForm {
                        offset: cursor.position(),
                        found,
                        introducer: "$$",
                    });
                }
                None => {
                    return Err(ParseFailure::UnexpectedEnd {
                        offset: cursor.position(),
                    });
                }
            },
            found => {
                return Err(ParseFailure::UnsupportedDatatypeForm {
                    offset: subtype_offset,
                    found,
                    introducer: "$",
                });
            }
        };
        Datatype { left, right: None }
    } else if code.is_ascii_digit() {
        let digit = usize::from(code - b'0');
        let left_index = digit
            .checked_mul(2)
            .ok_or(ParseFailure::ReferenceIndexOverflow {
                start: 0,
                index: digit,
            })?;
        let right_index =
            left_index
                .checked_add(1)
                .ok_or(ParseFailure::ReferenceIndexOverflow {
                    start: 0,
                    index: left_index,
                })?;
        let parameter_types =
            parameter_types.ok_or(ParseFailure::MissingParameterTypeReferences {
                offset,
                digit: code,
            })?;
        let left = budget.copy_string(parameter_types.reference(left_index)?)?;
        let right = match parameter_types.reference(right_index) {
            Ok(right) => Some(budget.copy_string(right)?),
            Err(ParseFailure::ReferenceOutOfHighWater { .. }) => None,
            Err(error) => return Err(error),
        };
        return Ok(Datatype { left, right });
    } else {
        return Err(ParseFailure::InvalidDatatypeCode {
            offset,
            found: code,
        });
    };

    if in_args {
        if let Some(parameter_types) = parameter_types {
            parameter_types.push_pair(&datatype.left, "", budget)?;
        }
    }
    Ok(datatype)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CallingConvention {
    calling_convention: Option<&'static str>,
    exported: Option<&'static str>,
}

pub(super) fn decode_calling_convention(
    byte: u8,
    flags: u16,
) -> Result<CallingConvention, ParseFailure> {
    if flags & (UNDNAME_NO_MS_KEYWORDS | UNDNAME_NO_ALLOCATION_LANGUAGE) != 0 {
        return Ok(CallingConvention {
            calling_convention: None,
            exported: None,
        });
    }

    let no_leading_underscores = flags & UNDNAME_NO_LEADING_UNDERSCORES != 0;
    let calling_convention = match byte {
        b'A' | b'B' => Some(if no_leading_underscores {
            "cdecl"
        } else {
            "__cdecl"
        }),
        b'C' | b'D' => Some(if no_leading_underscores {
            "pascal"
        } else {
            "__pascal"
        }),
        b'E' | b'F' => Some(if no_leading_underscores {
            "thiscall"
        } else {
            "__thiscall"
        }),
        b'G' | b'H' => Some(if no_leading_underscores {
            "stdcall"
        } else {
            "__stdcall"
        }),
        b'I' | b'J' => Some(if no_leading_underscores {
            "fastcall"
        } else {
            "__fastcall"
        }),
        b'K' | b'L' => None,
        b'M' => Some(if no_leading_underscores {
            "clrcall"
        } else {
            "__clrcall"
        }),
        found => return Err(ParseFailure::InvalidCallingConvention { found }),
    };
    let exported = if (byte - b'A') & 1 != 0 {
        Some(if no_leading_underscores {
            "dll_export "
        } else {
            "__dll_export "
        })
    } else {
        None
    };

    Ok(CallingConvention {
        calling_convention,
        exported,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Modifier {
    qualifier: Option<&'static str>,
    pointer_modifier: Option<&'static str>,
}

enum MemberFunctionModifier {
    Owned(String),
    Static(&'static str),
}

struct StandaloneFunctionParts {
    calling_convention: Option<&'static str>,
    exported: Option<&'static str>,
    return_type: Datatype,
    arguments: String,
}

struct MemberFunctionPointerParts {
    class: String,
    post_modifier: Option<MemberFunctionModifier>,
    calling_convention: Option<&'static str>,
    return_type: Datatype,
    arguments: String,
}

struct TemplateNameParts {
    literal: String,
    arguments: Option<String>,
}

impl MemberFunctionModifier {
    fn as_str(&self) -> &str {
        match self {
            Self::Owned(value) => value,
            Self::Static(value) => value,
        }
    }
}

pub(super) fn parse_modifier(
    cursor: &mut Cursor<'_>,
    flags: u16,
) -> Result<Modifier, ParseFailure> {
    let pointer_modifier = if cursor.peek(0) == Some(b'E') {
        cursor.advance(1)?;
        if flags & UNDNAME_NO_MS_KEYWORDS != 0 {
            None
        } else if flags & UNDNAME_NO_LEADING_UNDERSCORES != 0 {
            Some("ptr64")
        } else {
            Some("__ptr64")
        }
    } else {
        None
    };

    let offset = cursor.position();
    let code = cursor.next()?;
    let qualifier = match code {
        b'A' => None,
        b'B' => Some("const"),
        b'C' => Some("volatile"),
        b'D' => Some("const volatile"),
        found => return Err(ParseFailure::InvalidModifier { offset, found }),
    };

    Ok(Modifier {
        qualifier,
        pointer_modifier,
    })
}

pub(super) fn parse_literal_string(
    cursor: &mut Cursor<'_>,
    names: &mut RefArray,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let start = cursor.position();

    loop {
        match cursor.peek(0) {
            Some(b'@') if cursor.position() > start => {
                let end = cursor.position();
                cursor.advance(1)?;
                let bytes = cursor
                    .bytes(start, end)
                    .ok_or(ParseFailure::InvalidLiteralRange { start, end })?;
                let literal = std::str::from_utf8(bytes)
                    .map_err(|_| ParseFailure::InvalidLiteralRange { start, end })?;
                names.push(literal, budget)?;
                return budget.copy_string(literal);
            }
            Some(byte) if is_literal_byte(byte) => cursor.advance(1)?,
            found => {
                return Err(ParseFailure::InvalidLiteral {
                    offset: cursor.position(),
                    found,
                });
            }
        }
    }
}

#[cfg(test)]
fn parse_plain_class_name(
    cursor: &mut Cursor<'_>,
    names: &mut RefArray,
    stack: &mut RefArray,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let checkpoint = stack.logical_num();
    let result = parse_plain_class_components(cursor, names, stack, checkpoint, budget);
    match stack.restore_num(checkpoint) {
        Ok(()) => result,
        Err(restore_error) => Err(restore_error),
    }
}

#[cfg(test)]
fn parse_plain_class_components(
    cursor: &mut Cursor<'_>,
    names: &mut RefArray,
    stack: &mut RefArray,
    checkpoint: usize,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let mut output_len = 0_usize;
    loop {
        let has_previous = stack.logical_num() != checkpoint;
        let (component, next_output_len) = match cursor.peek(0) {
            Some(b'@') => {
                let terminator_offset = cursor.position();
                cursor.advance(1)?;
                if stack.logical_num() == checkpoint {
                    return Err(ParseFailure::EmptyClass {
                        offset: terminator_offset,
                    });
                }
                return render_class_name(stack, checkpoint, budget);
            }
            None => {
                return Err(ParseFailure::UnexpectedEnd {
                    offset: cursor.position(),
                });
            }
            Some(b'?') => {
                return Err(ParseFailure::UnsupportedClassComponent {
                    offset: cursor.position(),
                    found: b'?',
                });
            }
            Some(digit @ b'0'..=b'9') => {
                cursor.advance(1)?;
                let referenced = names.reference(usize::from(digit - b'0'))?;
                let next_output_len =
                    checked_class_output_len(output_len, referenced.len(), has_previous)?;
                stack.push(referenced, budget)?;
                output_len = next_output_len;
                continue;
            }
            Some(_) => {
                let component = parse_literal_string(cursor, names, budget)?;
                let next_output_len =
                    checked_class_output_len(output_len, component.len(), has_previous)?;
                (component, next_output_len)
            }
        };
        stack.push(&component, budget)?;
        output_len = next_output_len;
    }
}

fn checked_class_output_len(
    current_len: usize,
    component_len: usize,
    has_previous: bool,
) -> Result<usize, ParseFailure> {
    let output_len = current_len
        .checked_add(component_len)
        .and_then(|length| {
            if has_previous {
                length.checked_add(2)
            } else {
                Some(length)
            }
        })
        .ok_or(ParseFailure::OutputLimitExceeded {
            attempted: usize::MAX,
            limit: MAX_OUTPUT_BYTES,
        })?;
    if output_len > MAX_OUTPUT_BYTES {
        return Err(ParseFailure::OutputLimitExceeded {
            attempted: output_len,
            limit: MAX_OUTPUT_BYTES,
        });
    }
    Ok(output_len)
}

fn render_class_name(
    stack: &RefArray,
    start: usize,
    budget: &mut AttemptBudget,
) -> Result<String, ParseFailure> {
    let end = stack.logical_num();
    if start > end {
        return Err(ParseFailure::ActiveReferenceOutOfRange {
            index: start,
            num: end,
        });
    }

    let mut output_len = 0_usize;
    for index in start..end {
        let component = stack.active_absolute_reference(index)?;
        output_len = checked_class_output_len(output_len, component.len(), index > start)?;
    }

    let reservation = budget.preflight(output_len)?;
    let mut rendered = String::new();
    rendered
        .try_reserve_exact(output_len)
        .map_err(|_| ParseFailure::OutputAllocationFailed {
            additional: output_len,
        })?;
    let mut needs_separator = false;
    for index in (start..end).rev() {
        if needs_separator {
            rendered.push_str("::");
        }
        rendered.push_str(stack.active_absolute_reference(index)?);
        needs_separator = true;
    }
    budget.commit(reservation);
    Ok(rendered)
}

fn is_literal_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'<' | b'>')
}

#[cfg(test)]
mod tests {
    use super::{
        checked_class_output_len, decode_calling_convention, extended_primitive_type,
        is_literal_byte, ordinary_primitive_type, parse_datatype, parse_literal_string,
        parse_modifier, parse_number, parse_plain_class_name, render_class_name, CallingConvention,
        Datatype, MethodKind, Modifier, MsvcParser, MAX_ENCODED_NUMBER,
    };
    use crate::cursor::Cursor;
    use crate::error::ParseFailure;
    use crate::limits::{
        MAX_MSVC_NESTING_DEPTH as MAX_NESTING_DEPTH, MAX_OUTPUT_BYTES,
        MAX_STANDALONE_ARRAY_DIMENSIONS,
    };
    use crate::msvc::flags::{
        UNDNAME_COMPLETE, UNDNAME_NAME_ONLY, UNDNAME_NO_ALLOCATION_LANGUAGE,
        UNDNAME_NO_COMPLEX_TYPE, UNDNAME_NO_LEADING_UNDERSCORES, UNDNAME_NO_MS_KEYWORDS,
        VMP_DEMANGLE_FLAGS,
    };
    use crate::msvc::state::{AttemptBudget, RefArray};

    fn decode_tsv_string(field: &str) -> Result<String, &'static str> {
        if field.len() > MAX_OUTPUT_BYTES {
            return Err("fixture field exceeds the test decoder bound");
        }
        let body = field
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or("fixture string is not quoted")?;
        let mut decoded = String::new();
        decoded
            .try_reserve_exact(body.len())
            .map_err(|_| "fixture decoder allocation failed")?;
        let mut chars = body.chars();
        while let Some(character) = chars.next() {
            if character != '\\' {
                decoded.push(character);
                continue;
            }
            let escaped = chars.next().ok_or("truncated fixture escape")?;
            decoded.push(match escaped {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{0008}',
                'f' => '\u{000c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                _ => return Err("unsupported fixture escape"),
            });
        }
        Ok(decoded)
    }

    fn decode_template_fixture_row(
        line: &str,
    ) -> Result<Option<(String, String, usize, String)>, &'static str> {
        let mut fields = line.split('\t');
        let raw_field = fields.next().ok_or("missing raw fixture field")?;
        if !raw_field.starts_with("\"??$") || raw_field.as_bytes().get(4) == Some(&b'?') {
            return Ok(None);
        }
        let full_field = fields.next().ok_or("missing full fixture field")?;
        let name_pos_field = fields.next().ok_or("missing name position fixture field")?;
        let name_field = fields.next().ok_or("missing name fixture field")?;
        if fields.next().is_some() {
            return Err("extra fixture field");
        }
        let raw = decode_tsv_string(raw_field)?;
        let full = decode_tsv_string(full_field)?;
        let name_pos = name_pos_field
            .parse::<usize>()
            .map_err(|_| "invalid fixture name position")?;
        let name = decode_tsv_string(name_field)?;
        Ok(Some((raw, full, name_pos, name)))
    }

    #[test]
    fn named_datatypes_render_exact_prefixes_and_consume_class_names() {
        for flags in [UNDNAME_COMPLETE, VMP_DEMANGLE_FLAGS] {
            for (code, prefix) in [
                (b'T', "union "),
                (b'U', "struct "),
                (b'V', "class "),
                (b'Y', "cointerface "),
            ] {
                let input = [code, b'F', b'o', b'o', b'@', b'@', b'x'];
                let mut parser = MsvcParser::new(&input, flags).expect("input within limit");
                assert_eq!(
                    parser.parse_datatype(None, false),
                    Ok(Datatype {
                        left: format!("{prefix}Foo"),
                        right: None,
                    })
                );
                assert_eq!(parser.cursor.position(), 6);
                assert_eq!(parser.names.reference(0), Ok("Foo"));
                assert_eq!(parser.stack.logical_num(), 0);
            }
        }
    }

    #[test]
    fn named_template_class_components_render_exactly_and_preserve_cursor() {
        for (input, expected) in [
            (b"V?$Vec@H@@tail".as_slice(), "class Vec<int>"),
            (b"V?$Vec@H@ns@@tail", "class ns::Vec<int>"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Ok(Datatype {
                    left: expected.to_owned(),
                    right: None,
                })
            );
            assert_eq!(parser.cursor.peek(0), Some(b't'));
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn anonymous_namespace_components_replace_names_and_render_in_reverse() {
        for (input, expected) in [
            (b"V?A@@tail".as_slice(), "class `anonymous namespace'"),
            (b"V?A0x123@@tail", "class `anonymous namespace'"),
            (
                b"V?A0x123@Outer@@tail",
                "class Outer::`anonymous namespace'",
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Ok(Datatype {
                    left: expected.to_owned(),
                    right: None,
                })
            );
            assert_eq!(parser.cursor.peek(0), Some(b't'));
            assert_eq!(parser.names.reference(0), Ok("`anonymous namespace'"));
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn anonymous_namespace_replacement_obeys_scoped_digit_references() {
        let mut parser =
            MsvcParser::new(b"V?A0x@0@tail", UNDNAME_COMPLETE).expect("input within limit");
        parser
            .names
            .push("Old", &mut parser.budget)
            .expect("within limit");
        parser.names.set_start(1).expect("high-water boundary");

        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "class `anonymous namespace'::`anonymous namespace'".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.peek(0), Some(b't'));
        assert_eq!(parser.names.logical_start(), 1);
        assert_eq!(parser.names.logical_num(), 2);
        assert_eq!(parser.names.reference(0), Ok("`anonymous namespace'"));
    }

    #[test]
    fn anonymous_namespace_failures_preserve_exact_cursor_and_state() {
        for (input, expected) in [
            (
                b"V?A".as_slice(),
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: None,
                },
            ),
            (
                b"V?A!tail",
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: Some(b'!'),
                },
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), 3);
            assert_eq!(parser.names.logical_num(), 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let mut names_full =
            MsvcParser::new(b"V?A0x@@", UNDNAME_COMPLETE).expect("input within limit");
        names_full.names = RefArray::with_limit(0);
        assert_eq!(
            names_full.parse_datatype(None, false),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(names_full.cursor.position(), 6);
        assert_eq!(names_full.names.logical_num(), 0);

        let literal_cost = "A0x".len() * 2;
        let mut replacement_full =
            MsvcParser::new(b"V?A0x@@", UNDNAME_COMPLETE).expect("input within limit");
        replacement_full.budget = AttemptBudget::with_limit(literal_cost);
        assert_eq!(
            replacement_full.parse_datatype(None, false),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: literal_cost + "`anonymous namespace'".len(),
                limit: literal_cost,
            })
        );
        assert_eq!(replacement_full.cursor.position(), 6);
        assert_eq!(replacement_full.names.logical_num(), 1);
        assert_eq!(replacement_full.names.reference(0), Ok("A0x"));
        assert_eq!(replacement_full.stack.logical_num(), 0);
    }

    #[test]
    fn numeric_class_components_render_without_mutating_names() {
        for (input, expected) in [
            (b"V?0@tail".as_slice(), "class `1'"),
            (b"V?BA@@tail", "class `16'"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .names
                .push("Global", &mut parser.budget)
                .expect("within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Ok(Datatype {
                    left: expected.to_owned(),
                    right: None,
                })
            );
            assert_eq!(parser.cursor.peek(0), Some(b't'));
            assert_eq!(parser.names.logical_num(), 1);
            assert_eq!(parser.names.reference(0), Ok("Global"));
        }

        let mut parser =
            MsvcParser::new(b"V?0@V0@tail", UNDNAME_COMPLETE).expect("input within limit");
        parser
            .names
            .push("Global", &mut parser.budget)
            .expect("within limit");
        assert!(parser.parse_datatype(None, false).is_ok());
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Global".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.names.logical_num(), 1);
    }

    #[test]
    fn numeric_class_components_preserve_number_errors_and_question_order() {
        for (input, expected, position) in [
            (
                b"V?B!tail".as_slice(),
                ParseFailure::MissingNumberTerminator {
                    offset: 3,
                    found: Some(b'!'),
                },
                3,
            ),
            (
                b"V?!tail",
                ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: Some(b'!'),
                },
                2,
            ),
            (
                b"V?IAAAAAAA@@tail",
                ParseFailure::NumberOverflow {
                    start: 2,
                    offset: 9,
                    max: MAX_ENCODED_NUMBER,
                },
                10,
            ),
            (
                b"V??tail",
                ParseFailure::InvalidLiteral {
                    offset: 7,
                    found: None,
                },
                7,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn anonymous_and_numeric_components_propagate_capacity_and_budget_failures() {
        let mut anonymous =
            MsvcParser::new(b"V?A0x@@", UNDNAME_COMPLETE).expect("input within limit");
        anonymous.stack = RefArray::with_limit(0);
        assert_eq!(
            anonymous.parse_datatype(None, false),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(anonymous.cursor.position(), 6);
        assert_eq!(anonymous.names.reference(0), Ok("`anonymous namespace'"));

        let mut numeric = MsvcParser::new(b"V?0@", UNDNAME_COMPLETE).expect("input within limit");
        numeric.stack = RefArray::with_limit(0);
        assert_eq!(
            numeric.parse_datatype(None, false),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(numeric.cursor.position(), 3);
        assert_eq!(numeric.names.logical_num(), 0);

        let mut bounded =
            MsvcParser::new(b"V?0?0?0@", UNDNAME_COMPLETE).expect("input within limit");
        bounded.budget = AttemptBudget::with_limit(8);
        assert!(matches!(
            bounded.parse_datatype(None, false),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert!(bounded.budget.used() <= 8);
        assert_eq!(bounded.stack.logical_num(), 0);
    }

    #[test]
    fn anonymous_namespace_works_in_named_and_member_function_pointer_types() {
        for (input, expected_left, expected_right) in [
            (
                b"U?A0x@@tail".as_slice(),
                "struct `anonymous namespace'",
                None,
            ),
            (
                b"P8?A0x@@AAHXZtail",
                "int (__cdecl `anonymous namespace'::*",
                Some(")(void)"),
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Ok(Datatype {
                    left: expected_left.to_owned(),
                    right: expected_right.map(str::to_owned),
                })
            );
            assert_eq!(parser.cursor.peek(0), Some(b't'));
        }
    }

    #[test]
    fn template_argument_failure_falls_back_to_literal_after_exact_consumption() {
        let mut parser =
            MsvcParser::new(b"V?$Pair@H0@@tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Pair".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.position(), 11);
        assert_eq!(parser.cursor.peek(0), Some(b'@'));
        assert_eq!(parser.names.logical_start(), 0);
        assert_eq!(parser.names.logical_num(), 1);
        assert_eq!(parser.names.reference(0), Ok("Pair"));
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(
            parser.budget.used(),
            36,
            "failed local argument parsing must not refund its allocations"
        );
    }

    #[test]
    fn malformed_template_components_restore_name_scope_and_stack_safely() {
        for (input, expected, position) in [
            (
                b"V?".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 2 },
                2,
            ),
            (
                b"V?X",
                ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: Some(b'X'),
                },
                2,
            ),
            (
                b"V?$",
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: None,
                },
                3,
            ),
            (
                b"V?$@",
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: Some(b'@'),
                },
                3,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .names
                .push("Global", &mut parser.budget)
                .expect("default name table has capacity");
            parser
                .stack
                .push("seed", &mut parser.budget)
                .expect("default stack has capacity");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.names.logical_start(), 0);
            assert_eq!(parser.names.logical_num(), 1);
            assert_eq!(parser.names.reference(0), Ok("Global"));
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("seed"));
        }

        let mut fallback =
            MsvcParser::new(b"V?$Vec@!@tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            fallback.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Vec".to_owned(),
                right: None,
            })
        );
        assert_eq!(fallback.cursor.peek(0), Some(b't'));
    }

    #[test]
    fn template_final_name_is_global_and_available_to_later_class_digits() {
        let mut parser =
            MsvcParser::new(b"V?$Vec@H@0@tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Vec<int>::Vec<int>".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.peek(0), Some(b't'));
        assert_eq!(parser.names.logical_num(), 1);
        assert_eq!(parser.names.reference(0), Ok("Vec<int>"));
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(parser.stack.reference(0), Ok("Vec<int>"));
        assert_eq!(parser.stack.reference(1), Ok("Vec<int>"));
    }

    #[test]
    fn nested_and_function_pointer_template_arguments_reuse_recursive_grammar() {
        for (input, expected) in [
            (
                b"V?$Outer@V?$Inner@H@@@@tail".as_slice(),
                "class Outer<class Inner<int> >",
            ),
            (b"V?$Fn@P6AHXZ@@tail", "class Fn<int (__cdecl*)(void)>"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Ok(Datatype {
                    left: expected.to_owned(),
                    right: None,
                })
            );
            assert_eq!(parser.cursor.peek(0), Some(b't'));
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn template_component_table_failures_are_atomic_and_restore_scope() {
        let mut names_full =
            MsvcParser::new(b"V?$Vec@H@@", UNDNAME_COMPLETE).expect("input within limit");
        names_full.names = RefArray::with_limit(0);
        assert_eq!(
            names_full.parse_datatype(None, false),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(names_full.cursor.position(), 7);
        assert_eq!(names_full.names.logical_start(), 0);
        assert_eq!(names_full.names.logical_num(), 0);
        assert_eq!(names_full.stack.logical_num(), 0);

        let mut stack_full =
            MsvcParser::new(b"V?$Vec@H@@", UNDNAME_COMPLETE).expect("input within limit");
        stack_full.stack = RefArray::with_limit(0);
        assert_eq!(
            stack_full.parse_datatype(None, false),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(stack_full.cursor.position(), 9);
        assert_eq!(stack_full.cursor.peek(0), Some(b'@'));
        assert_eq!(stack_full.names.logical_start(), 0);
        assert_eq!(stack_full.names.logical_num(), 1);
        assert_eq!(stack_full.names.reference(0), Ok("Vec<int>"));
        assert_eq!(stack_full.stack.logical_num(), 0);
    }

    #[test]
    fn template_arguments_use_a_fresh_local_parameter_reference_table() {
        let mut parser =
            MsvcParser::new(b"V?$Pair@_H0@@tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Pair<__int32,__int32>".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.peek(0), Some(b't'));
        assert_eq!(parser.names.logical_num(), 1);
        assert_eq!(parser.names.reference(0), Ok("Pair<__int32,__int32>"));
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn template_name_scope_hides_outer_names_and_restores_logical_state() {
        let mut parser =
            MsvcParser::new(b"V?$Pair@V0@@@tail", UNDNAME_COMPLETE).expect("input within limit");
        parser
            .names
            .push("Global", &mut parser.budget)
            .expect("default name table has capacity");
        let start = parser.names.logical_start();
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Pair<class Pair>".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.peek(0), Some(b't'));
        assert_eq!(parser.names.logical_start(), start);
        assert_eq!(parser.names.logical_num(), 2);
        assert_eq!(parser.names.reference(0), Ok("Global"));
        assert_eq!(parser.names.reference(1), Ok("Pair<class Pair>"));
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn member_function_pointer_accepts_template_class_components() {
        let input = b"P8?$Vec@H@@AAHXZtail";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "int (__cdecl Vec<int>::*".to_owned(),
                right: Some(")(void)".to_owned()),
            })
        );
        assert_eq!(parser.cursor.peek(0), Some(b't'));
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn named_class_dispatch_supports_qualification_and_scoped_digit_backreferences() {
        let mut qualified =
            MsvcParser::new(b"VInner@Outer@@tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            qualified.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Outer::Inner".to_owned(),
                right: None,
            })
        );
        assert_eq!(qualified.cursor.position(), 14);
        assert_eq!(qualified.stack.logical_num(), 0);

        let mut referenced =
            MsvcParser::new(b"V0@tail", UNDNAME_COMPLETE).expect("input within limit");
        referenced
            .names
            .push("Old", &mut referenced.budget)
            .expect("default name table has capacity");
        referenced
            .names
            .push("Scoped", &mut referenced.budget)
            .expect("default name table has capacity");
        referenced
            .names
            .set_start(1)
            .expect("inside name high water");
        assert_eq!(
            referenced.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Scoped".to_owned(),
                right: None,
            })
        );
        assert_eq!(referenced.cursor.position(), 3);
        assert_eq!(referenced.stack.logical_num(), 0);
    }

    #[test]
    fn no_complex_type_strips_all_named_type_prefixes() {
        for input in [
            b"TFoo@@".as_slice(),
            b"UFoo@@",
            b"VFoo@@",
            b"YFoo@@",
            b"W4Foo@@",
        ] {
            let mut parser =
                MsvcParser::new(input, UNDNAME_NO_COMPLEX_TYPE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Ok(Datatype {
                    left: "Foo".to_owned(),
                    right: None,
                })
            );
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn enum_dispatch_peeks_subtype_and_preserves_class_failures() {
        let mut valid =
            MsvcParser::new(b"W4Foo@@tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            valid.parse_datatype(None, false),
            Ok(Datatype {
                left: "enum Foo".to_owned(),
                right: None,
            })
        );
        assert_eq!(valid.cursor.position(), 7);

        let mut eof = MsvcParser::new(b"W", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            eof.parse_datatype(None, false),
            Err(ParseFailure::UnexpectedEnd { offset: 1 })
        );
        assert_eq!(eof.cursor.position(), 1);

        let mut invalid = MsvcParser::new(b"W!tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            invalid.parse_datatype(None, false),
            Err(ParseFailure::UnsupportedDatatypeForm {
                offset: 1,
                found: b'!',
                introducer: "W",
            })
        );
        assert_eq!(invalid.cursor.position(), 1);
        assert_eq!(invalid.cursor.peek(0), Some(b'!'));

        let mut malformed_class =
            MsvcParser::new(b"W4?@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            malformed_class.parse_datatype(None, false),
            Err(ParseFailure::InvalidNumberStart {
                offset: 3,
                found: Some(b'@'),
            })
        );
        assert_eq!(malformed_class.cursor.position(), 3);
        assert_eq!(malformed_class.stack.logical_num(), 0);
    }

    #[test]
    fn named_datatypes_add_atomic_pmt_pairs_only_for_arguments() {
        let mut budget = AttemptBudget::new();
        for input in [
            b"TFoo@@".as_slice(),
            b"UFoo@@",
            b"VFoo@@",
            b"YFoo@@",
            b"W4Foo@@",
        ] {
            let mut pmt = RefArray::with_limit(2);
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let datatype = parser
                .parse_datatype(Some(&mut pmt), true)
                .expect("valid named datatype");
            assert_eq!(pmt.reference(0), Ok(datatype.left.as_str()));
            assert_eq!(pmt.reference(1), Ok(""));

            let mut pmt = RefArray::with_limit(2);
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert!(parser.parse_datatype(Some(&mut pmt), false).is_ok());
            assert!(matches!(
                pmt.reference(0),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 0, .. })
            ));

            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert!(parser.parse_datatype(None, true).is_ok());

            let mut full_pmt = RefArray::with_limit(2);
            full_pmt
                .push("seed", &mut budget)
                .expect("first slot has capacity");
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(Some(&mut full_pmt), true),
                Err(ParseFailure::ReferenceLimitExceeded {
                    attempted: 3,
                    limit: 2,
                })
            );
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(full_pmt.reference(0), Ok("seed"));
            assert!(matches!(
                full_pmt.reference(1),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 1, .. })
            ));
        }
    }

    #[test]
    fn invalid_numeric_class_component_consumes_question_and_rolls_back_stack() {
        for input in [b"T?@".as_slice(), b"U?@", b"V?@", b"Y?@"] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Err(ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: Some(b'@'),
                })
            );
            assert_eq!(parser.cursor.position(), 2);
            assert_eq!(parser.cursor.peek(0), Some(b'@'));
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn parser_datatype_fallback_matches_free_leaf_parser() {
        let mut budget = AttemptBudget::new();
        for input in [b"Ctail".as_slice(), b"_Dtail", b"$00tail"] {
            let mut method_pmt = RefArray::with_limit(8);
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let method = parser.parse_datatype(Some(&mut method_pmt), true);

            let mut free_pmt = RefArray::with_limit(8);
            let mut free_cursor = Cursor::new(input);
            let free = parse_datatype(&mut free_cursor, Some(&mut free_pmt), true, &mut budget);
            assert_eq!(method, free);
            assert_eq!(parser.cursor.position(), free_cursor.position());
            assert_eq!(method_pmt.logical_num(), free_pmt.logical_num());
            for index in 0..method_pmt.logical_num() {
                assert_eq!(method_pmt.reference(index), free_pmt.reference(index));
            }
        }

        let mut method_pmt = RefArray::with_limit(2);
        method_pmt
            .push_pair("left", "right", &mut budget)
            .expect("pair fits");
        let mut parser = MsvcParser::new(b"0tail", UNDNAME_COMPLETE).expect("input within limit");
        let method = parser.parse_datatype(Some(&mut method_pmt), false);
        let mut free_pmt = RefArray::with_limit(2);
        free_pmt
            .push_pair("left", "right", &mut budget)
            .expect("pair fits");
        let mut free_cursor = Cursor::new(b"0tail");
        let free = parse_datatype(&mut free_cursor, Some(&mut free_pmt), false, &mut budget);
        assert_eq!(method, free);
        assert_eq!(parser.cursor.position(), free_cursor.position());
    }

    #[test]
    fn parser_uses_default_bounded_name_and_stack_tables() {
        let mut parser = MsvcParser::new(b"", UNDNAME_COMPLETE).expect("input within limit");
        for _ in 0..crate::limits::MAX_BACKREFERENCES {
            parser
                .names
                .push("", &mut parser.budget)
                .expect("within default name limit");
            parser
                .stack
                .push("", &mut parser.budget)
                .expect("within default stack limit");
        }
        assert_eq!(
            parser.names.push("", &mut parser.budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: crate::limits::MAX_BACKREFERENCES + 1,
                limit: crate::limits::MAX_BACKREFERENCES,
            })
        );
        assert_eq!(
            parser.stack.push("", &mut parser.budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: crate::limits::MAX_BACKREFERENCES + 1,
                limit: crate::limits::MAX_BACKREFERENCES,
            })
        );
        assert_eq!(parser.flags, UNDNAME_COMPLETE);
    }

    #[test]
    fn argument_lists_stop_exactly_and_validate_required_z() {
        for (input, expected, position) in [
            (b"XZ".as_slice(), "(void)", 2),
            (b"HXZ", "(int)", 3),
            (b"H@Z", "(int)", 3),
            (b"HZZ", "(int,...)", 3),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let mut pmt = RefArray::new();
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), true, b'(', b')'),
                Ok(expected.to_owned())
            );
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.depth, 0);
        }
    }

    #[test]
    fn argument_lists_preserve_null_parameter_type_reference_semantics() {
        let mut without_references =
            MsvcParser::new(b"_H0@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            without_references.parse_arguments(None, false, b'(', b')'),
            Err(ParseFailure::MissingParameterTypeReferences {
                offset: 2,
                digit: b'0',
            })
        );
        assert_eq!(without_references.cursor.position(), 3);
        assert_eq!(without_references.cursor.peek(0), Some(b'@'));

        let mut with_references =
            MsvcParser::new(b"_H0@", UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::new();
        assert_eq!(
            with_references.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Ok("(__int32,__int32)".to_owned())
        );
        assert_eq!(with_references.cursor.position(), 4);
        assert_eq!(pmt.logical_num(), 2);
    }

    #[test]
    fn argument_lists_reject_non_ascii_delimiters_before_side_effects() {
        for (open, close) in [(0x80, b')'), (b'(', 0xff)] {
            let mut parser = MsvcParser::new(b"_H@", UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_arguments(None, false, open, close),
                Err(ParseFailure::InvalidArgumentDelimiter { open, close })
            );
            assert_eq!(parser.cursor.position(), 0);
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.budget.used(), 0);
        }
    }

    #[test]
    fn argument_list_terminator_errors_consume_mismatches_but_not_eof() {
        for (input, expected_position) in [(b"H@!".as_slice(), 3), (b"X!", 2), (b"Z!", 2)] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let mut pmt = RefArray::new();
            let offset = expected_position - 1;
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), true, b'(', b')'),
                Err(ParseFailure::InvalidArgumentListTerminator {
                    offset,
                    found: b'!',
                })
            );
            assert_eq!(parser.cursor.position(), expected_position);
        }

        for input in [b"".as_slice(), b"H", b"H@"] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let mut pmt = RefArray::new();
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), true, b'(', b')'),
                Err(ParseFailure::UnexpectedEnd {
                    offset: input.len(),
                })
            );
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn unterminated_argument_lists_accept_at_eof_and_single_void() {
        for (input, expected, position) in [
            (b"H@".as_slice(), "(int)", 2),
            (b"H", "(int)", 1),
            (b"X@", "(void)", 2),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let mut pmt = RefArray::new();
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
                Ok(expected.to_owned())
            );
            assert_eq!(parser.cursor.position(), position);
        }
    }

    #[test]
    fn argument_rendering_joins_complete_left_and_right_values() {
        let mut parser = MsvcParser::new(b"H_DZZ", UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::new();
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), true, b'(', b')'),
            Ok("(int,__int8,...)".to_owned())
        );
        assert_eq!(parser.cursor.position(), 5);

        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair("left", "right", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"0@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Ok("(leftright)".to_owned())
        );
    }

    #[test]
    fn angle_argument_lists_skip_only_exact_markers_and_space_nested_closings() {
        for marker in [b"$$V".as_slice(), b"$$Z"] {
            let mut input = b"H".to_vec();
            input.extend_from_slice(marker);
            input.push(b'@');
            let mut parser = MsvcParser::new(&input, UNDNAME_COMPLETE).expect("input within limit");
            let mut pmt = RefArray::new();
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), false, b'<', b'>'),
                Ok("<int>".to_owned())
            );
            assert_eq!(parser.cursor.position(), input.len());
        }

        let mut parser = MsvcParser::new(b"H$$V@", UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::new();
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Err(ParseFailure::UnsupportedDatatypeForm {
                offset: 3,
                found: b'V',
                introducer: "$$",
            })
        );
        assert_eq!(parser.cursor.position(), 3);

        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair("Foo", ">", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"0@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'<', b'>'),
            Ok("<Foo> >".to_owned())
        );
    }

    #[test]
    fn argument_lists_share_parameter_type_state_and_preserve_capacity_failures() {
        let mut pmt = RefArray::with_limit(8);
        let mut parser = MsvcParser::new(b"_D0@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Ok("(__int8,__int8)".to_owned())
        );
        assert_eq!(pmt.logical_num(), 2);
        assert_eq!(pmt.reference(0), Ok("__int8"));
        assert_eq!(pmt.reference(1), Ok(""));

        for (input, expected) in [(b"VFoo@@@".as_slice(), "(class Foo)"), (b"PAH@", "(int *)")] {
            let mut pmt = RefArray::with_limit(4);
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
                Ok(expected.to_owned())
            );
            assert_eq!(pmt.logical_num(), 2);
        }

        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(3);
        pmt.push_pair("seed", "tail", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"_D@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 3,
            })
        );
        assert_eq!(parser.cursor.position(), 2);
        assert_eq!(pmt.logical_num(), 2);
        assert_eq!(pmt.reference(0), Ok("seed"));
        assert_eq!(pmt.reference(1), Ok("tail"));
    }

    #[test]
    fn argument_limit_is_checked_before_parsing_and_after_markers_and_at() {
        let mut exact = vec![b'H'; crate::limits::MAX_ARGUMENTS];
        exact.push(b'@');
        let mut parser = MsvcParser::new(&exact, UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::new();
        let rendered = parser
            .parse_arguments(Some(&mut pmt), false, b'(', b')')
            .expect("exact limit is accepted");
        assert_eq!(
            rendered.matches("int").count(),
            crate::limits::MAX_ARGUMENTS
        );
        assert_eq!(parser.cursor.position(), exact.len());

        let over = vec![b'H'; crate::limits::MAX_ARGUMENTS + 1];
        let mut parser = MsvcParser::new(&over, UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::new();
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Err(ParseFailure::ArgumentLimitExceeded {
                attempted: crate::limits::MAX_ARGUMENTS + 1,
                limit: crate::limits::MAX_ARGUMENTS,
            })
        );
        assert_eq!(parser.cursor.position(), crate::limits::MAX_ARGUMENTS);
        assert_eq!(parser.cursor.peek(0), Some(b'H'));

        let mut marked = vec![b'H'; crate::limits::MAX_ARGUMENTS];
        marked.extend_from_slice(b"$$V@");
        let mut parser = MsvcParser::new(&marked, UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::new();
        assert!(parser
            .parse_arguments(Some(&mut pmt), false, b'<', b'>')
            .is_ok());
        assert_eq!(parser.cursor.position(), marked.len());
    }

    #[test]
    fn cumulative_argument_copies_are_bounded_before_retaining_another_argument() {
        let component = "x".repeat(200_000);
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair(&component, "", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"000@", UNDNAME_COMPLETE).expect("input within limit");
        parser.budget = AttemptBudget::with_limit(1_000_000);
        assert_eq!(
            parser.parse_arguments(Some(&mut pmt), false, b'(', b')'),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 1_200_000,
                limit: 1_000_000,
            })
        );
        assert_eq!(parser.cursor.position(), 3);
        assert_eq!(parser.budget.used(), 1_000_000);
    }

    #[test]
    fn malformed_angle_markers_use_datatype_cursor_semantics_and_restore_depth() {
        for input in [b"$".as_slice(), b"$$"] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let mut pmt = RefArray::new();
            assert_eq!(
                parser.parse_arguments(Some(&mut pmt), false, b'<', b'>'),
                Err(ParseFailure::UnexpectedEnd {
                    offset: input.len(),
                })
            );
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn cumulative_budget_rejects_named_backreference_copy_before_prefix_allocation() {
        let mut parser = MsvcParser::new(b"V0@", UNDNAME_COMPLETE).expect("input within limit");
        parser
            .names
            .push(&"x".repeat(MAX_OUTPUT_BYTES), &mut parser.budget)
            .expect("single name fits reference table");
        assert_eq!(
            parser.parse_datatype(None, false),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: MAX_OUTPUT_BYTES * 2,
                limit: MAX_OUTPUT_BYTES,
            })
        );
        assert_eq!(parser.cursor.position(), 2);
        assert_eq!(parser.cursor.peek(0), Some(b'@'));
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn cumulative_attempt_budget_bounds_repeated_named_arguments_and_pmt_storage() {
        let component = "x".repeat(64 * 1024);
        let input = b"V0@".repeat(8);
        let mut parser = MsvcParser::new(&input, UNDNAME_COMPLETE).expect("input within limit");
        parser
            .names
            .push(&component, &mut parser.budget)
            .expect("single component fits attempt budget");
        let mut pmt = RefArray::with_limit(16);

        for _ in 0..3 {
            parser
                .parse_datatype(Some(&mut pmt), true)
                .expect("first three expansions fit cumulative budget");
        }
        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), true),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: MAX_OUTPUT_BYTES + 42,
                limit: MAX_OUTPUT_BYTES,
            })
        );
        assert_eq!(parser.cursor.position(), 12);
        assert_eq!(pmt.logical_num(), 6);
        assert_eq!(parser.budget.used(), 983_076);
        assert!(parser.budget.used() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn parser_input_limit_accepts_exact_boundary_and_rejects_one_over() {
        let exact = vec![b'x'; crate::limits::MAX_INPUT_BYTES];
        assert!(MsvcParser::new(&exact, UNDNAME_COMPLETE).is_ok());

        let over = vec![b'x'; crate::limits::MAX_INPUT_BYTES + 1];
        assert!(matches!(
            MsvcParser::new(&over, UNDNAME_COMPLETE),
            Err(ParseFailure::InputLimitExceeded {
                attempted,
                limit: crate::limits::MAX_INPUT_BYTES,
            }) if attempted == crate::limits::MAX_INPUT_BYTES + 1
        ));
    }

    fn assert_parser_datatype(input: &[u8], flags: u16, in_args: bool, expected_left: &str) {
        let mut parser = MsvcParser::new(input, flags).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, in_args),
            Ok(Datatype {
                left: expected_left.to_owned(),
                right: None,
            }),
            "input {:?}",
            String::from_utf8_lossy(input)
        );
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn recursive_dollar_one_uses_full_nested_symbol_and_preserves_template_delimiter() {
        for (input, flags, expected) in [
            (
                b"$1?g@@YAHXZ".as_slice(),
                UNDNAME_COMPLETE,
                "&int __cdecl g(void)",
            ),
            (b"$1?h@@3HA", UNDNAME_COMPLETE, "&int h"),
            (
                b"$1??HC@@QAEHH@Z",
                UNDNAME_COMPLETE,
                "&public: int __thiscall C::operator+(int)",
            ),
            (
                b"$1??__E?x@@3HA@@YAXXZ",
                UNDNAME_COMPLETE,
                "&void __cdecl `dynamic initializer for 'int x''(void)",
            ),
        ] {
            assert_parser_datatype(input, flags, false, expected);
        }

        for (input, flags, expected, name_pos) in [
            (
                b"?f@?$C@$1?g@@YAHXZ@@YAXXZ".as_slice(),
                UNDNAME_COMPLETE,
                "void __cdecl C<&int __cdecl g(void)>::f(void)",
                13,
            ),
            (
                b"?f@?$C@$1?g@@YAHXZ@@YAXXZ",
                VMP_DEMANGLE_FLAGS,
                "void C<&int g(void)>::f(void)",
                5,
            ),
            (
                b"?f@?$C@$1?g@@YAHXZ@@YAXXZ",
                UNDNAME_NAME_ONLY,
                "C<&g>::f",
                0,
            ),
            (
                b"?f@?$C@$1?h@@3HA@@YAXXZ",
                UNDNAME_COMPLETE,
                "void __cdecl C<&int h>::f(void)",
                13,
            ),
            (
                b"?f@?$C@$1?h@@3HA@@YAXXZ",
                VMP_DEMANGLE_FLAGS,
                "void C<&int h>::f(void)",
                5,
            ),
            (b"?f@?$C@$1?h@@3HA@@YAXXZ", UNDNAME_NAME_ONLY, "C<&h>::f", 0),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let parsed = parser
                .parse_symbol()
                .expect("recursive symbol template argument");
            assert_eq!(parsed.full_name(), expected);
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn recursive_dollar_one_embedded_template_budget_is_exact_and_cumulative() {
        let input = b"?f@?$C@$1?g@@YAHXZ@@YAXXZ";
        let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        assert!(measured.parse_symbol().is_ok());
        let exact_cost = measured.budget.used();

        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        exact.budget = AttemptBudget::with_limit(exact_cost);
        assert!(exact.parse_symbol().is_ok());
        assert_eq!(exact.budget.used(), exact_cost);
        assert_eq!(exact.cursor.position(), input.len());

        let mut one_under = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        one_under.budget = AttemptBudget::with_limit(exact_cost - 1);
        assert!(matches!(
            one_under.parse_symbol(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(one_under.cursor.position(), input.len());
        assert_eq!(one_under.stack.logical_num(), 0);
    }

    #[test]
    fn recursive_dollar_one_restores_nested_state_and_retains_name_high_water() {
        let mut parser =
            MsvcParser::new(b"$1?g@@YAHXZ", UNDNAME_COMPLETE).expect("input within limit");
        parser
            .stack
            .push("OuterStack", &mut parser.budget)
            .expect("active stack seed");
        parser
            .stack
            .push("HistoricalStack", &mut parser.budget)
            .expect("historical stack seed");
        parser.stack.restore_num(1).expect("valid stack rollback");
        parser
            .names
            .push("OuterName", &mut parser.budget)
            .expect("name seed");
        let names_start = parser.names.logical_start();
        let names_num = parser.names.logical_num();

        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "&int __cdecl g(void)".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.stack.logical_num(), 1);
        assert_eq!(parser.stack.reference(0), Ok("OuterStack"));
        assert_eq!(parser.stack.reference(1), Ok("HistoricalStack"));
        assert_eq!(parser.names.logical_start(), names_start);
        assert_eq!(parser.names.logical_num(), names_num);
        assert_eq!(parser.names.reference(0), Ok("OuterName"));
        assert_eq!(parser.names.reference(1), Ok("g"));
        assert_eq!(parser.depth, 0);
    }

    #[test]
    fn recursive_dollar_one_pmt_pair_is_atomic_and_uses_full_nested_result() {
        let input = b"$1?g@@YAHXZ";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        let mut pmt = RefArray::with_limit(2);
        assert!(parser.parse_datatype(Some(&mut pmt), true).is_ok());
        assert_eq!(pmt.logical_num(), 2);
        assert_eq!(pmt.reference(0), Ok("&int __cdecl g(void)"));
        assert_eq!(pmt.reference(1), Ok(""));
        let exact_cost = parser.budget.used();

        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        exact.budget = AttemptBudget::with_limit(exact_cost);
        let mut exact_pmt = RefArray::with_limit(2);
        assert!(exact.parse_datatype(Some(&mut exact_pmt), true).is_ok());
        assert_eq!(exact.budget.used(), exact_cost);

        let mut one_under = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        one_under.budget = AttemptBudget::with_limit(exact_cost - 1);
        let mut one_under_pmt = RefArray::with_limit(2);
        assert!(matches!(
            one_under.parse_datatype(Some(&mut one_under_pmt), true),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(one_under.cursor.position(), input.len());
        assert_eq!(one_under_pmt.logical_num(), 0);

        let mut full = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        let mut full_pmt = RefArray::with_limit(1);
        assert_eq!(
            full.parse_datatype(Some(&mut full_pmt), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(full.cursor.position(), input.len());
        assert_eq!(full_pmt.logical_num(), 0);

        let mut seed_budget = AttemptBudget::new();
        let mut historical_pmt = RefArray::with_limit(2);
        historical_pmt
            .push_pair("old-left", "old-right", &mut seed_budget)
            .expect("historical pair seed");
        historical_pmt
            .restore_num(0)
            .expect("valid PMT high-water rollback");
        let mut high_water = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        assert!(high_water
            .parse_datatype(Some(&mut historical_pmt), true)
            .is_ok());
        assert_eq!(historical_pmt.logical_num(), 2);
        assert_eq!(historical_pmt.reference(0), Ok("&int __cdecl g(void)"));
        assert_eq!(historical_pmt.reference(1), Ok(""));

        for (pmt, in_args) in [(true, false), (false, true)] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let mut table = RefArray::with_limit(0);
            let result = if pmt {
                parser.parse_datatype(Some(&mut table), in_args)
            } else {
                parser.parse_datatype(None, in_args)
            };
            assert!(result.is_ok());
            assert_eq!(table.logical_num(), 0);
        }
    }

    #[test]
    fn recursive_dollar_one_malformed_nested_symbols_keep_typed_cursor_semantics() {
        for (input, expected, position) in [
            (
                b"$".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 1 },
                1,
            ),
            (
                b"$1",
                ParseFailure::InvalidMsvcPrefix {
                    offset: 2,
                    found: None,
                },
                2,
            ),
            (
                b"$1!",
                ParseFailure::InvalidMsvcPrefix {
                    offset: 2,
                    found: Some(b'!'),
                },
                2,
            ),
            (
                b"$1?g@@YAH!",
                ParseFailure::InvalidDatatypeCode {
                    offset: 9,
                    found: b'!',
                },
                10,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .stack
                .push("OuterStack", &mut parser.budget)
                .expect("stack seed");
            parser
                .names
                .push("OuterName", &mut parser.budget)
                .expect("name seed");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("OuterStack"));
            assert_eq!(parser.names.logical_num(), 1);
            assert_eq!(parser.names.reference(0), Ok("OuterName"));
            assert_eq!(parser.depth, 0);
        }
    }

    #[test]
    fn recursive_dollar_one_shares_datatype_and_symbol_depth() {
        let mut exact =
            MsvcParser::new(b"$1?g@@YAHXZ", UNDNAME_COMPLETE).expect("input within limit");
        exact.depth = MAX_NESTING_DEPTH - 3;
        assert!(exact.parse_datatype(None, false).is_ok());
        assert_eq!(exact.depth, MAX_NESTING_DEPTH - 3);

        let mut over =
            MsvcParser::new(b"$1?g@@YAHXZ", UNDNAME_COMPLETE).expect("input within limit");
        over.depth = MAX_NESTING_DEPTH - 2;
        assert_eq!(
            over.parse_datatype(None, false),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(over.cursor.peek(0), Some(b'H'));
        assert_eq!(over.depth, MAX_NESTING_DEPTH - 2);
        assert_eq!(over.stack.logical_num(), 0);
    }

    #[test]
    fn recursive_dollar_c_renders_exact_qualifiers_and_ignores_pointer_modifier() {
        for (input, expected) in [
            (b"$$CAH".as_slice(), "int "),
            (b"$$CBH", "int const"),
            (b"$$CCH", "int volatile"),
            (b"$$CDH", "int const volatile"),
            (b"$$CEBH", "int const"),
        ] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, false, expected);
        }
        assert_parser_datatype(b"$$CEBH", UNDNAME_NO_MS_KEYWORDS, false, "int const");
    }

    #[test]
    fn recursive_dollar_q_uses_modified_type_rendering_before_rvalue_suffix() {
        for (input, in_args, expected) in [
            (b"$$QAH".as_slice(), false, "int &&"),
            (b"$$QBH", false, "int const &&"),
            (b"$$QEAH", false, "int &&"),
            (b"$$QFAH", false, "int &&"),
            (b"$$QAPAH", false, "int * &&"),
            (b"$$QAY04H", false, "int ()[5] &&"),
            (b"$$QAPAPAH", false, "int ** &&"),
            (b"$$QAPAPAH", true, "int ** &&"),
        ] {
            assert_parser_datatype(input, UNDNAME_NO_MS_KEYWORDS, in_args, expected);
        }
    }

    #[test]
    fn recursive_dollar_forms_preserve_subtype_pmt_quirks_and_add_one_outer_pair() {
        let mut primitive_pmt = RefArray::with_limit(2);
        let mut primitive =
            MsvcParser::new(b"$$CAH", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            primitive.parse_datatype(Some(&mut primitive_pmt), true),
            Ok(Datatype {
                left: "int ".to_owned(),
                right: None,
            })
        );
        assert_eq!(primitive_pmt.logical_num(), 2);
        assert_eq!(primitive_pmt.reference(0), Ok("int "));
        assert_eq!(primitive_pmt.reference(1), Ok(""));

        let mut extended_pmt = RefArray::with_limit(4);
        let mut extended =
            MsvcParser::new(b"$$CA_H", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            extended.parse_datatype(Some(&mut extended_pmt), true),
            Ok(Datatype {
                left: "__int32 ".to_owned(),
                right: None,
            })
        );
        assert_eq!(extended_pmt.logical_num(), 4);
        assert_eq!(extended_pmt.reference(0), Ok("__int32"));
        assert_eq!(extended_pmt.reference(1), Ok(""));
        assert_eq!(extended_pmt.reference(2), Ok("__int32 "));
        assert_eq!(extended_pmt.reference(3), Ok(""));

        let mut q_pmt = RefArray::with_limit(2);
        let mut q = MsvcParser::new(b"$$QAH", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            q.parse_datatype(Some(&mut q_pmt), true),
            Ok(Datatype {
                left: "int &&".to_owned(),
                right: None,
            })
        );
        assert_eq!(q_pmt.logical_num(), 2);
        assert_eq!(q_pmt.reference(0), Ok("int &&"));
        assert_eq!(q_pmt.reference(1), Ok(""));
    }

    #[test]
    fn recursive_dollar_forms_preserve_digit_right_and_outer_pair_contents() {
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(4);
        pmt.push_pair("base", "suffix", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"$$QA0", UNDNAME_COMPLETE).expect("input within limit");

        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), true),
            Ok(Datatype {
                left: "base &&".to_owned(),
                right: Some("suffix".to_owned()),
            })
        );
        assert_eq!(parser.cursor.position(), 5);
        assert_eq!(pmt.logical_num(), 4);
        assert_eq!(pmt.reference(2), Ok("base &&"));
        assert_eq!(pmt.reference(3), Ok("suffix"));
    }

    #[test]
    fn recursive_dollar_c_keeps_recursive_pair_when_outer_pair_is_full() {
        let mut pmt = RefArray::with_limit(2);
        let mut parser = MsvcParser::new(b"$$CA_H", UNDNAME_COMPLETE).expect("input within limit");

        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 2,
            })
        );
        assert_eq!(parser.cursor.position(), 6);
        assert_eq!(pmt.logical_num(), 2);
        assert_eq!(pmt.reference(0), Ok("__int32"));
        assert_eq!(pmt.reference(1), Ok(""));
        assert_eq!(parser.budget.used(), 22);
    }

    #[test]
    fn recursive_dollar_outer_pair_capacity_failure_is_atomic_and_uncharged() {
        for input in [b"$$CAH".as_slice(), b"$$QAH"] {
            let mut seed_budget = AttemptBudget::new();
            let mut pmt = RefArray::with_limit(3);
            pmt.push_pair("base", "suffix", &mut seed_budget)
                .expect("seed pair fits");
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let expected_used = if input == b"$$CAH" { 7 } else { 12 };

            assert_eq!(
                parser.parse_datatype(Some(&mut pmt), true),
                Err(ParseFailure::ReferenceLimitExceeded {
                    attempted: 4,
                    limit: 3,
                })
            );
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(pmt.logical_num(), 2);
            assert_eq!(pmt.reference(0), Ok("base"));
            assert_eq!(pmt.reference(1), Ok("suffix"));
            assert_eq!(parser.budget.used(), expected_used);
        }
    }

    #[test]
    fn recursive_dollar_forms_charge_exact_append_and_pmt_copy_budgets() {
        let mut exact_c = MsvcParser::new(b"$$CAH", UNDNAME_COMPLETE).expect("input within limit");
        exact_c.budget = AttemptBudget::with_limit(11);
        let mut c_pmt = RefArray::with_limit(2);
        assert!(exact_c.parse_datatype(Some(&mut c_pmt), true).is_ok());
        assert_eq!(exact_c.budget.used(), 11);

        let mut over_c = MsvcParser::new(b"$$CAH", UNDNAME_COMPLETE).expect("input within limit");
        over_c.budget = AttemptBudget::with_limit(10);
        let mut c_pmt = RefArray::with_limit(2);
        assert_eq!(
            over_c.parse_datatype(Some(&mut c_pmt), true),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 11,
                limit: 10,
            })
        );
        assert_eq!(over_c.cursor.position(), 5);
        assert_eq!(c_pmt.logical_num(), 0);
        assert_eq!(over_c.budget.used(), 7);

        let mut exact_q = MsvcParser::new(b"$$QAH", UNDNAME_COMPLETE).expect("input within limit");
        exact_q.budget = AttemptBudget::with_limit(18);
        let mut q_pmt = RefArray::with_limit(2);
        assert!(exact_q.parse_datatype(Some(&mut q_pmt), true).is_ok());
        assert_eq!(exact_q.budget.used(), 18);

        let mut over_q = MsvcParser::new(b"$$QAH", UNDNAME_COMPLETE).expect("input within limit");
        over_q.budget = AttemptBudget::with_limit(17);
        let mut q_pmt = RefArray::with_limit(2);
        assert_eq!(
            over_q.parse_datatype(Some(&mut q_pmt), true),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 18,
                limit: 17,
            })
        );
        assert_eq!(over_q.cursor.position(), 5);
        assert_eq!(q_pmt.logical_num(), 0);
        assert_eq!(over_q.budget.used(), 12);
    }

    #[test]
    fn recursive_dollar_truncation_and_invalid_modifiers_have_exact_cursor() {
        for (input, expected, position) in [
            (
                b"$".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 1 },
                1,
            ),
            (b"$$", ParseFailure::UnexpectedEnd { offset: 2 }, 2),
            (b"$$C", ParseFailure::UnexpectedEnd { offset: 3 }, 3),
            (b"$$CE", ParseFailure::UnexpectedEnd { offset: 4 }, 4),
            (b"$$Q", ParseFailure::UnexpectedEnd { offset: 3 }, 3),
            (b"$$QE", ParseFailure::UnexpectedEnd { offset: 4 }, 4),
            (
                b"$$C!",
                ParseFailure::InvalidModifier {
                    offset: 3,
                    found: b'!',
                },
                4,
            ),
            (
                b"$$Q!",
                ParseFailure::InvalidModifier {
                    offset: 3,
                    found: b'!',
                },
                4,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        for input in [&[b'$', b'$', b'C', 0xff][..], &[b'$', b'$', b'Q', 0xff]] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Err(ParseFailure::InvalidModifier {
                    offset: 3,
                    found: 0xff,
                })
            );
            assert_eq!(parser.cursor.position(), 4);
        }
    }

    #[test]
    fn recursive_dollar_dispatch_leaves_other_double_dollar_forms_unchanged() {
        let mut parser = MsvcParser::new(b"$$XH", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, false),
            Err(ParseFailure::UnsupportedDatatypeForm {
                offset: 2,
                found: b'X',
                introducer: "$$",
            })
        );
        assert_eq!(parser.cursor.position(), 2);
        assert_eq!(parser.cursor.peek(0), Some(b'X'));
        assert_parser_datatype(b"$$T", UNDNAME_COMPLETE, false, "std::nullptr_t");
    }

    #[test]
    fn recursive_dollar_b_renders_optional_dimensions_and_consumes_exactly() {
        for (input, expected) in [
            (b"$$BH".as_slice(), "int "),
            (b"$$BYA@H", "int "),
            (b"$$BY04H", "int [5]"),
            (b"$$BY10?0H", "int [1][-1]"),
        ] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, false, expected);
        }

        let mut parser =
            MsvcParser::new(b"$$BY104Htail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "int [1][5]".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.position(), 8);
        assert_eq!(parser.cursor.peek(0), Some(b't'));
    }

    #[test]
    fn recursive_dollar_b_has_no_native_128_dimension_cap() {
        let mut input = b"$$BYIB@".to_vec();
        input.extend(std::iter::repeat_n(b'0', 129));
        input.extend_from_slice(b"Htail");
        let mut parser = MsvcParser::new(&input, UNDNAME_COMPLETE).expect("input within limit");

        let datatype = parser
            .parse_datatype(None, false)
            .expect("standalone array consumes every declared dimension");
        assert_eq!(datatype.left.matches("[1]").count(), 129);
        assert!(datatype.left.starts_with("int "));
        assert_eq!(parser.cursor.position(), 137);
        assert_eq!(parser.cursor.peek(0), Some(b't'));
    }

    #[test]
    fn recursive_dollar_b_preflights_dimension_limit_before_first_dimension() {
        let input = b"$$BYBAAB@0H";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");

        assert_eq!(
            parser.parse_datatype(None, false),
            Err(ParseFailure::ArrayDimensionLimitExceeded {
                attempted: MAX_STANDALONE_ARRAY_DIMENSIONS + 1,
                limit: MAX_STANDALONE_ARRAY_DIMENSIONS,
            })
        );
        assert_eq!(parser.cursor.position(), 9);
        assert_eq!(parser.cursor.peek(0), Some(b'0'));
    }

    #[test]
    fn recursive_dollar_b_rejects_negative_count_but_accepts_negative_zero() {
        let mut negative =
            MsvcParser::new(b"$$BY?0H", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            negative.parse_datatype(None, false),
            Err(ParseFailure::NegativeArrayDimensionCount {
                offset: 4,
                value: -1,
            })
        );
        assert_eq!(negative.cursor.position(), 6);
        assert_eq!(negative.cursor.peek(0), Some(b'H'));

        assert_parser_datatype(b"$$BY?A@H", UNDNAME_COMPLETE, false, "int ");
    }

    #[test]
    fn malformed_recursive_dollar_b_arrays_have_exact_cursor() {
        for (input, expected, position) in [
            (
                b"$$B".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 3 },
                3,
            ),
            (
                b"$$BY",
                ParseFailure::InvalidNumberStart {
                    offset: 4,
                    found: None,
                },
                4,
            ),
            (
                b"$$BY?",
                ParseFailure::InvalidNumberStart {
                    offset: 5,
                    found: None,
                },
                5,
            ),
            (
                b"$$BY10",
                ParseFailure::InvalidNumberStart {
                    offset: 6,
                    found: None,
                },
                6,
            ),
            (
                b"$$BY1BA!",
                ParseFailure::MissingNumberTerminator {
                    offset: 7,
                    found: Some(b'!'),
                },
                7,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.depth, 0);
        }
    }

    #[test]
    fn recursive_dollar_b_preserves_recursive_pmt_effects_and_subtype_right() {
        let mut primitive_pmt = RefArray::with_limit(2);
        let mut primitive =
            MsvcParser::new(b"$$BY04H", UNDNAME_COMPLETE).expect("input within limit");
        assert!(primitive
            .parse_datatype(Some(&mut primitive_pmt), true)
            .is_ok());
        assert_eq!(primitive_pmt.reference(0), Ok("int [5]"));
        assert_eq!(primitive_pmt.reference(1), Ok(""));

        let mut extended_pmt = RefArray::with_limit(4);
        let mut extended = MsvcParser::new(b"$$B_H", UNDNAME_COMPLETE).expect("input within limit");
        assert!(extended
            .parse_datatype(Some(&mut extended_pmt), true)
            .is_ok());
        assert_eq!(extended_pmt.reference(0), Ok("__int32"));
        assert_eq!(extended_pmt.reference(1), Ok(""));
        assert_eq!(extended_pmt.reference(2), Ok("__int32 "));
        assert_eq!(extended_pmt.reference(3), Ok(""));

        let mut capacity_two = RefArray::with_limit(2);
        let mut capacity_failure =
            MsvcParser::new(b"$$B_H", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            capacity_failure.parse_datatype(Some(&mut capacity_two), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 2,
            })
        );
        assert_eq!(capacity_failure.cursor.position(), 5);
        assert_eq!(capacity_two.logical_num(), 2);
        assert_eq!(capacity_two.reference(0), Ok("__int32"));
        assert_eq!(capacity_two.reference(1), Ok(""));

        let mut seed_budget = AttemptBudget::new();
        let mut digit_pmt = RefArray::with_limit(4);
        digit_pmt
            .push_pair("base", "suffix", &mut seed_budget)
            .expect("seed pair fits");
        let mut digit = MsvcParser::new(b"$$B0", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            digit.parse_datatype(Some(&mut digit_pmt), true),
            Ok(Datatype {
                left: "base ".to_owned(),
                right: Some("suffix".to_owned()),
            })
        );
        assert_eq!(digit_pmt.reference(2), Ok("base "));
        assert_eq!(digit_pmt.reference(3), Ok("suffix"));
    }

    #[test]
    fn recursive_dollar_b_outer_pmt_failure_is_atomic_and_keeps_parse_charges() {
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(3);
        pmt.push_pair("base", "suffix", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"$$BY04H", UNDNAME_COMPLETE).expect("input within limit");

        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 3,
            })
        );
        assert_eq!(parser.cursor.position(), 7);
        assert_eq!(pmt.logical_num(), 2);
        assert_eq!(pmt.reference(0), Ok("base"));
        assert_eq!(pmt.reference(1), Ok("suffix"));
        assert_eq!(parser.budget.used(), 15);
    }

    #[test]
    fn recursive_dollar_b_subtype_recursion_obeys_depth_guard() {
        let mut exact = MsvcParser::new(b"$$BH", UNDNAME_COMPLETE).expect("input within limit");
        exact.depth = MAX_NESTING_DEPTH - 2;
        assert!(exact.parse_datatype(None, false).is_ok());
        assert_eq!(exact.cursor.position(), 4);
        assert_eq!(exact.depth, MAX_NESTING_DEPTH - 2);

        let mut over = MsvcParser::new(b"$$BH", UNDNAME_COMPLETE).expect("input within limit");
        over.depth = MAX_NESTING_DEPTH - 1;
        assert_eq!(
            over.parse_datatype(None, false),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(over.cursor.position(), 3);
        assert_eq!(over.cursor.peek(0), Some(b'H'));
        assert_eq!(over.depth, MAX_NESTING_DEPTH - 1);
    }

    #[test]
    fn recursive_dollar_depth_guard_accepts_limit_and_restores_depth_and_stack() {
        for wrapper in ["$$B", "$$CA", "$$QA"] {
            let exact_input = format!("{}H", wrapper.repeat(MAX_NESTING_DEPTH - 1));
            let mut exact = MsvcParser::new(exact_input.as_bytes(), UNDNAME_COMPLETE)
                .expect("input within limit");
            exact
                .stack
                .push("seed", &mut exact.budget)
                .expect("stack seed fits");
            assert!(exact.parse_datatype(None, false).is_ok());
            assert_eq!(exact.cursor.position(), exact_input.len());
            assert_eq!(exact.depth, 0);
            assert_eq!(exact.stack.logical_num(), 1);

            let over_input = format!("{}H", wrapper.repeat(MAX_NESTING_DEPTH));
            let mut over = MsvcParser::new(over_input.as_bytes(), UNDNAME_COMPLETE)
                .expect("input within limit");
            over.stack
                .push("seed", &mut over.budget)
                .expect("stack seed fits");
            assert_eq!(
                over.parse_datatype(None, false),
                Err(ParseFailure::NestingLimitExceeded {
                    attempted: MAX_NESTING_DEPTH + 1,
                    limit: MAX_NESTING_DEPTH,
                })
            );
            assert_eq!(over.cursor.position(), MAX_NESTING_DEPTH * wrapper.len());
            assert_eq!(over.cursor.peek(0), Some(b'H'));
            assert_eq!(over.depth, 0);
            assert_eq!(over.stack.logical_num(), 1);
        }
    }

    #[test]
    fn recursive_depth_boundary_is_safe_on_small_thread_stack_subprocess() {
        const CHILD_ENV: &str = "VMP_DEMANGLE_SMALL_STACK_CHILD";
        const TEST_NAME: &str =
            "msvc::parser::tests::recursive_depth_boundary_is_safe_on_small_thread_stack_subprocess";

        if std::env::var_os(CHILD_ENV).is_some() {
            let child = std::thread::Builder::new()
                // Rust 1.97 debug frames at the accepted depth need more than
                // 64 KiB on Linux and Windows. Keep this bounded and small,
                // but leave cross-platform headroom for compiler ABI/layout
                // differences; the parser's production depth cap remains 6.
                .stack_size(256 * 1024)
                .spawn(|| {
                    for (wrapper, suffix) in [
                        ("PA", ""),
                        ("$$B", ""),
                        ("$$CA", ""),
                        ("$$QA", ""),
                        ("P6A", "XZ"),
                        ("$$A6A", "XZ"),
                        ("P8Foo@@AA", "XZ"),
                    ] {
                        let exact_input = format!(
                            "{}H{}",
                            wrapper.repeat(MAX_NESTING_DEPTH - 1),
                            suffix.repeat(MAX_NESTING_DEPTH - 1)
                        );
                        let mut exact = MsvcParser::new(exact_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("exact-depth input is within the input limit");
                        assert!(exact.parse_datatype(None, false).is_ok());
                        assert_eq!(exact.depth, 0);

                        let over_input = format!(
                            "{}H{}",
                            wrapper.repeat(MAX_NESTING_DEPTH),
                            suffix.repeat(MAX_NESTING_DEPTH)
                        );
                        let mut over = MsvcParser::new(over_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("one-over input is within the input limit");
                        assert_eq!(
                            over.parse_datatype(None, false),
                            Err(ParseFailure::NestingLimitExceeded {
                                attempted: MAX_NESTING_DEPTH + 1,
                                limit: MAX_NESTING_DEPTH,
                            })
                        );
                        assert_eq!(over.depth, 0);
                    }

                    let exact_method_input =
                        format!("?f@@YA{}HXZ", "PA".repeat(MAX_NESTING_DEPTH - 1));
                    let mut exact_method =
                        MsvcParser::new(exact_method_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("exact-depth method input is within the input limit");
                    assert!(exact_method.parse_symbol().is_ok());
                    assert_eq!(exact_method.depth, 0);

                    let over_method_input = format!("?f@@YA{}HXZ", "PA".repeat(MAX_NESTING_DEPTH));
                    let mut over_method =
                        MsvcParser::new(over_method_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("one-over method input is within the input limit");
                    assert_eq!(
                        over_method.parse_symbol(),
                        Err(ParseFailure::NestingLimitExceeded {
                            attempted: MAX_NESTING_DEPTH + 1,
                            limit: MAX_NESTING_DEPTH,
                        })
                    );
                    assert_eq!(over_method.depth, 0);

                    let exact_nested =
                        wrap_nested_symbol("?g@@YA@XZ".to_owned(), MAX_NESTING_DEPTH - 1);
                    let mut exact_nested_parser =
                        MsvcParser::new(exact_nested.as_bytes(), UNDNAME_COMPLETE)
                            .expect("exact nested input is within the input limit");
                    assert!(exact_nested_parser.parse_symbol().is_ok());
                    assert_eq!(exact_nested_parser.depth, 0);

                    let over_nested = wrap_nested_symbol("?g@@YA@XZ".to_owned(), MAX_NESTING_DEPTH);
                    let mut over_nested_parser =
                        MsvcParser::new(over_nested.as_bytes(), UNDNAME_COMPLETE)
                            .expect("one-over nested input is within the input limit");
                    assert_eq!(
                        over_nested_parser.parse_symbol(),
                        Err(ParseFailure::NestingLimitExceeded {
                            attempted: MAX_NESTING_DEPTH + 1,
                            limit: MAX_NESTING_DEPTH,
                        })
                    );
                    assert_eq!(over_nested_parser.depth, 0);

                    let exact_dynamic =
                        wrap_dynamic_symbol(String::from("?g@@YA@XZ"), MAX_NESTING_DEPTH - 1);
                    let mut exact_dynamic_parser =
                        MsvcParser::new(exact_dynamic.as_bytes(), UNDNAME_COMPLETE)
                            .expect("exact dynamic input is within the input limit");
                    assert!(exact_dynamic_parser.parse_symbol().is_ok());
                    assert_eq!(exact_dynamic_parser.depth, 0);

                    let over_dynamic =
                        wrap_dynamic_symbol(String::from("?g@@YA@XZ"), MAX_NESTING_DEPTH);
                    let mut over_dynamic_parser =
                        MsvcParser::new(over_dynamic.as_bytes(), UNDNAME_COMPLETE)
                            .expect("one-over dynamic input is within the input limit");
                    assert_eq!(
                        over_dynamic_parser.parse_symbol(),
                        Err(ParseFailure::NestingLimitExceeded {
                            attempted: MAX_NESTING_DEPTH + 1,
                            limit: MAX_NESTING_DEPTH,
                        })
                    );
                    assert_eq!(over_dynamic_parser.depth, 0);

                    let exact_dollar_one_input =
                        format!("$1?g@@YA{}HXZ", "PA".repeat(MAX_NESTING_DEPTH - 3));
                    let mut exact_dollar_one =
                        MsvcParser::new(exact_dollar_one_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("exact $1 input is within the input limit");
                    assert!(exact_dollar_one.parse_datatype(None, false).is_ok());
                    assert_eq!(exact_dollar_one.depth, 0);

                    let over_dollar_one_input =
                        format!("$1?g@@YA{}HXZ", "PA".repeat(MAX_NESTING_DEPTH - 2));
                    let mut over_dollar_one =
                        MsvcParser::new(over_dollar_one_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("one-over $1 input is within the input limit");
                    assert_eq!(
                        over_dollar_one.parse_datatype(None, false),
                        Err(ParseFailure::NestingLimitExceeded {
                            attempted: MAX_NESTING_DEPTH + 1,
                            limit: MAX_NESTING_DEPTH,
                        })
                    );
                    assert_eq!(over_dollar_one.depth, 0);

                    let exact_template_input = format!(
                        "{}H{}",
                        "V?$T@".repeat(MAX_NESTING_DEPTH - 1),
                        "@@".repeat(MAX_NESTING_DEPTH - 1)
                    );
                    let mut exact_template =
                        MsvcParser::new(exact_template_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("exact-depth template input is within the input limit");
                    assert!(exact_template.parse_datatype(None, false).is_ok());
                    assert_eq!(exact_template.depth, 0);

                    let over_template_input = format!(
                        "{}H{}",
                        "V?$T@".repeat(MAX_NESTING_DEPTH),
                        "@@".repeat(MAX_NESTING_DEPTH)
                    );
                    let mut over_template =
                        MsvcParser::new(over_template_input.as_bytes(), UNDNAME_COMPLETE)
                            .expect("one-over template input is within the input limit");
                    // get_template_name intentionally falls back to its literal
                    // when the nested argument parser reaches the depth guard.
                    assert!(over_template.parse_datatype(None, false).is_ok());
                    assert_eq!(over_template.depth, 0);
                })
                .expect("small-stack parser thread must start");
            child
                .join()
                .expect("small-stack parser thread must not abort");
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
    fn recursive_dollar_q_restores_stack_on_named_subtype_success_and_failure() {
        let mut success =
            MsvcParser::new(b"$$QAVFoo@@", UNDNAME_COMPLETE).expect("input within limit");
        success
            .stack
            .push("seed", &mut success.budget)
            .expect("stack seed fits");
        assert!(success.parse_datatype(None, false).is_ok());
        assert_eq!(success.stack.logical_num(), 1);
        assert_eq!(success.stack.reference(1), Ok("Foo"));

        let mut failure =
            MsvcParser::new(b"$$QAVFoo@?", UNDNAME_COMPLETE).expect("input within limit");
        failure
            .stack
            .push("seed", &mut failure.budget)
            .expect("stack seed fits");
        assert_eq!(
            failure.parse_datatype(None, false),
            Err(ParseFailure::UnexpectedEnd { offset: 10 })
        );
        assert_eq!(failure.depth, 0);
        assert_eq!(failure.stack.logical_num(), 1);
        assert_eq!(failure.stack.reference(0), Ok("seed"));
    }

    #[test]
    fn ordinary_modified_types_render_exactly_and_preserve_c_pointer_quirks() {
        for (input, expected) in [
            (b"AAH".as_slice(), "int &"),
            (b"BAH", "int & volatile"),
            (b"PAH", "int *"),
            (b"QAH", "int * const"),
            (b"RAH", "int * volatile"),
            (b"SAH", "int * const volatile"),
        ] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, true, expected);
        }
        for input in [b"QAH".as_slice(), b"RAH", b"SAH"] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, false, "int *");
        }
        assert_parser_datatype(b"PAPAH", UNDNAME_COMPLETE, false, "int **");
        assert_parser_datatype(b"PAPAH", UNDNAME_COMPLETE, true, "int * *");
        assert_parser_datatype(b"PAVFoo@@", UNDNAME_COMPLETE, false, "class Foo *");
    }

    #[test]
    fn modified_array_pointer_renders_and_consumes_exactly() {
        let mut parser =
            MsvcParser::new(b"PAY04Htail", UNDNAME_COMPLETE).expect("input within limit");

        assert_eq!(
            parser.parse_datatype(None, false),
            Ok(Datatype {
                left: "int (*)[5]".to_owned(),
                right: None,
            })
        );
        assert_eq!(parser.cursor.position(), 6);
        assert_eq!(parser.cursor.peek(0), Some(b't'));
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn modified_arrays_preserve_native_modifier_spacing_and_dimension_order() {
        for (input, expected) in [
            (b"AAY04H".as_slice(), "int (&)[5]"),
            (b"PBY04H", "int (const *)[5]"),
            (b"PEAY04H", "int (* __ptr64)[5]"),
            (b"PEIFAY04H", "int (__unaligned * __ptr64 __restrict)[5]"),
            (b"PAY104H", "int (*)[1][5]"),
            (b"PAYA@C", "signed char (*)"),
            (b"PAY?A@H", "int (*)"),
            (b"PAY0?0H", "int (*)[-1]"),
        ] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, false, expected);
        }
        assert_parser_datatype(
            b"PEAY04H",
            UNDNAME_NO_LEADING_UNDERSCORES,
            false,
            "int (* ptr64)[5]",
        );
        assert_parser_datatype(b"PEAY04H", UNDNAME_NO_MS_KEYWORDS, false, "int (*)[5]");
    }

    #[test]
    fn modified_array_count_is_capped_at_128_and_negative_count_is_rejected() {
        let mut capped_input = b"PAYIB@".to_vec();
        capped_input.extend(std::iter::repeat_n(b'0', 128));
        capped_input.extend_from_slice(b"Htail");
        let mut capped =
            MsvcParser::new(&capped_input, UNDNAME_COMPLETE).expect("input within limit");
        let datatype = capped
            .parse_datatype(None, false)
            .expect("native count cap accepts exactly 128 dimensions");
        assert_eq!(datatype.left.matches("[1]").count(), 128);
        assert!(datatype.left.starts_with("int (*)"));
        assert_eq!(capped.cursor.position(), 135);
        assert_eq!(capped.cursor.peek(0), Some(b't'));

        let mut negative =
            MsvcParser::new(b"PAY?0H", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            negative.parse_datatype(None, false),
            Err(ParseFailure::NegativeArrayDimensionCount {
                offset: 3,
                value: -1,
            })
        );
        assert_eq!(negative.cursor.position(), 5);
        assert_eq!(negative.cursor.peek(0), Some(b'H'));
        assert_eq!(negative.stack.logical_num(), 0);
    }

    #[test]
    fn malformed_modified_arrays_have_exact_cursor_and_restore_the_stack() {
        for (input, expected, cursor) in [
            (
                b"PAY".as_slice(),
                ParseFailure::InvalidNumberStart {
                    offset: 3,
                    found: None,
                },
                3,
            ),
            (
                b"PAY?",
                ParseFailure::InvalidNumberStart {
                    offset: 4,
                    found: None,
                },
                4,
            ),
            (
                b"PAY10",
                ParseFailure::InvalidNumberStart {
                    offset: 5,
                    found: None,
                },
                5,
            ),
            (
                b"PAY0BA!",
                ParseFailure::MissingNumberTerminator {
                    offset: 6,
                    found: Some(b'!'),
                },
                6,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .stack
                .push("seed", &mut parser.budget)
                .expect("stack seed fits");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), cursor);
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("seed"));
        }
    }

    #[test]
    fn modified_arrays_preserve_subtype_right_and_add_outer_pmt_pair_atomically() {
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(4);
        pmt.push_pair("base", "suffix", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser =
            MsvcParser::new(b"PAY040tail", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), true),
            Ok(Datatype {
                left: "base (*)[5]".to_owned(),
                right: Some("suffix".to_owned()),
            })
        );
        assert_eq!(parser.cursor.position(), 6);
        assert_eq!(pmt.reference(2), Ok("base (*)[5]"));
        assert_eq!(pmt.reference(3), Ok("suffix"));

        let mut full = RefArray::with_limit(3);
        full.push_pair("base", "suffix", &mut seed_budget)
            .expect("seed pair fits");
        let mut failure = MsvcParser::new(b"PAY040", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            failure.parse_datatype(Some(&mut full), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 3,
            })
        );
        assert_eq!(failure.cursor.position(), 6);
        assert_eq!(full.logical_num(), 2);
        assert_eq!(full.reference(0), Ok("base"));
        assert_eq!(full.reference(1), Ok("suffix"));
    }

    #[test]
    fn modified_array_subtype_recursion_obeys_the_depth_guard() {
        let mut exact = MsvcParser::new(b"PAYA@H", UNDNAME_COMPLETE).expect("input within limit");
        exact.depth = MAX_NESTING_DEPTH - 2;
        assert!(exact.parse_datatype(None, false).is_ok());
        assert_eq!(exact.cursor.position(), 6);
        assert_eq!(exact.depth, MAX_NESTING_DEPTH - 2);

        let mut over = MsvcParser::new(b"PAYA@H", UNDNAME_COMPLETE).expect("input within limit");
        over.depth = MAX_NESTING_DEPTH - 1;
        assert_eq!(
            over.parse_datatype(None, false),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(over.cursor.position(), 5);
        assert_eq!(over.cursor.peek(0), Some(b'H'));
        assert_eq!(over.depth, MAX_NESTING_DEPTH - 1);
    }

    #[test]
    fn modified_array_dimensions_charge_cumulative_attempt_budget() {
        let mut input = b"PAYIB@".to_vec();
        input.extend(std::iter::repeat_n(b'0', 128));
        input.extend_from_slice(b"V0@");
        let component = "x".repeat(350_000);
        let mut parser = MsvcParser::new(&input, UNDNAME_COMPLETE).expect("input within limit");
        parser
            .names
            .push(&component, &mut parser.budget)
            .expect("seed component fits");

        assert!(matches!(
            parser.parse_datatype(None, false),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(parser.cursor.position(), input.len());
        assert!(parser.budget.used() <= MAX_OUTPUT_BYTES);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn modified_type_extensions_flags_and_qualifiers_render_exactly() {
        for (input, expected) in [
            (b"PEAH".as_slice(), "int * __ptr64"),
            (b"PIAH", "int * __restrict"),
            (b"PEIAH", "int * __ptr64 __restrict"),
            (b"PFAH", "int __unaligned *"),
            (b"PEIFAH", "int __unaligned * __ptr64 __restrict"),
            (b"PBH", "int const *"),
            (b"PCH", "int volatile *"),
            (b"PDH", "int const volatile *"),
            (b"PEEAH", "int * __ptr64"),
            (b"PFEAH", "int __unaligned *"),
        ] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, false, expected);
        }
        for (input, expected) in [
            (b"PEAH".as_slice(), "int * ptr64"),
            (b"PIAH", "int * restrict"),
            (b"PEIAH", "int * ptr64 restrict"),
            (b"PFAH", "int unaligned *"),
        ] {
            assert_parser_datatype(input, UNDNAME_NO_LEADING_UNDERSCORES, false, expected);
        }
        for input in [b"PEAH".as_slice(), b"PIAH", b"PEIAH", b"PFAH"] {
            assert_parser_datatype(input, UNDNAME_NO_MS_KEYWORDS, false, "int *");
        }
    }

    #[test]
    fn question_datatype_is_argument_template_parameter_or_transparent_modifier() {
        for (input, expected) in [
            (b"?0".as_slice(), "`template-parameter-1'"),
            (b"??0", "`template-parameter--1'"),
            (b"?BA@", "`template-parameter-16'"),
        ] {
            assert_parser_datatype(input, UNDNAME_COMPLETE, true, expected);
        }
        assert_parser_datatype(b"?AH", UNDNAME_COMPLETE, false, "int");
    }

    #[test]
    fn modified_and_template_datatypes_add_atomic_outer_pmt_pairs() {
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(4);
        pmt.push_pair("base", "suffix", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser = MsvcParser::new(b"PA0", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), true),
            Ok(Datatype {
                left: "base *".to_owned(),
                right: Some("suffix".to_owned()),
            })
        );
        assert_eq!(parser.cursor.position(), 3);
        assert_eq!(pmt.reference(2), Ok("base *"));
        assert_eq!(pmt.reference(3), Ok("suffix"));

        let mut template_pmt = RefArray::with_limit(2);
        let mut template = MsvcParser::new(b"?BA@", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            template.parse_datatype(Some(&mut template_pmt), true),
            Ok(Datatype {
                left: "`template-parameter-16'".to_owned(),
                right: None,
            })
        );
        assert_eq!(template.cursor.position(), 4);
        assert_eq!(template_pmt.reference(0), Ok("`template-parameter-16'"));
        assert_eq!(template_pmt.reference(1), Ok(""));

        for input in [b"PAH".as_slice(), b"?0"] {
            let mut full_pmt = RefArray::with_limit(2);
            full_pmt
                .push("seed", &mut seed_budget)
                .expect("first slot fits");
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(Some(&mut full_pmt), true),
                Err(ParseFailure::ReferenceLimitExceeded {
                    attempted: 3,
                    limit: 2,
                })
            );
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(full_pmt.reference(0), Ok("seed"));
            assert!(matches!(
                full_pmt.reference(1),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 1, .. })
            ));
            assert_eq!(parser.depth, 0);
        }
    }

    #[test]
    fn modified_type_failures_have_exact_cursor_and_stack_semantics() {
        for (input, expected) in [
            (b"P".as_slice(), ParseFailure::UnexpectedEnd { offset: 1 }),
            (b"PE", ParseFailure::UnexpectedEnd { offset: 2 }),
            (b"PEI", ParseFailure::UnexpectedEnd { offset: 3 }),
            (b"PF", ParseFailure::UnexpectedEnd { offset: 2 }),
            (
                b"P!",
                ParseFailure::InvalidModifier {
                    offset: 1,
                    found: b'!',
                },
            ),
            (
                &[b'P', 0xff][..],
                ParseFailure::InvalidModifier {
                    offset: 1,
                    found: 0xff,
                },
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        for (input, introducer, found) in [(b"P1tail", "P", b'1'), (b"Q1tail", "Q", b'1')] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Err(ParseFailure::UnsupportedDatatypeForm {
                    offset: 1,
                    found,
                    introducer,
                })
            );
            assert_eq!(parser.cursor.position(), 2);
        }

        let mut q_eof = MsvcParser::new(b"Q", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            q_eof.parse_datatype(None, false),
            Err(ParseFailure::UnexpectedEnd { offset: 1 })
        );
        assert_eq!(q_eof.cursor.position(), 1);
    }

    #[test]
    fn member_function_pointer_datatypes_render_exact_class_left_right_and_cursor() {
        for (input, expected_left) in [
            (b"P8Foo@@AAHXZ".as_slice(), "int (__cdecl Foo::*"),
            (b"P8Inner@Outer@@AAHXZ", "int (__cdecl Outer::Inner::*"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid member function pointer datatype");
            assert_eq!(datatype.left, expected_left);
            assert_eq!(datatype.right.as_deref(), Some(")(void)"));
            assert_eq!(
                format!("{})(void)", datatype.left),
                format!("{expected_left})(void)")
            );
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn member_function_pointer_modifiers_and_calling_conventions_match_source() {
        for (input, flags, expected_left, expected_right) in [
            (
                b"P8Foo@@AAHXZ".as_slice(),
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void)",
            ),
            (
                b"P8Foo@@BAHXZ",
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void) const",
            ),
            (
                b"P8Foo@@CAHXZ",
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void) volatile",
            ),
            (
                b"P8Foo@@DAHXZ",
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void) const volatile",
            ),
            (
                b"P8Foo@@EAAHXZ",
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void) __ptr64",
            ),
            (
                b"P8Foo@@EBAHXZ",
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void) const __ptr64",
            ),
            (
                b"P8Foo@@AAHXZ",
                UNDNAME_NO_LEADING_UNDERSCORES,
                "int (cdecl Foo::*",
                ")(void)",
            ),
            (
                b"P8Foo@@EAAHXZ",
                UNDNAME_NO_LEADING_UNDERSCORES,
                "int (cdecl Foo::*",
                ")(void) ptr64",
            ),
            (
                b"P8Foo@@AAHXZ",
                UNDNAME_NO_ALLOCATION_LANGUAGE,
                "int (__cdecl Foo::*",
                ")(void)",
            ),
            (b"P8Foo@@AKHXZ", UNDNAME_COMPLETE, "int (Foo::*", ")(void)"),
            (
                b"P8Foo@@ABHXZ",
                UNDNAME_COMPLETE,
                "int (__cdecl Foo::*",
                ")(void)",
            ),
            (
                &[
                    b'P', b'8', b'F', b'o', b'o', b'@', b'@', b'E', b'A', 0xff, b'H', b'X', b'Z',
                ],
                UNDNAME_NO_MS_KEYWORDS,
                "int (Foo::*",
                ")(void)",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid member function pointer modifiers");
            assert_eq!(datatype.left, expected_left);
            assert_eq!(datatype.right.as_deref(), Some(expected_right));
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn member_function_pointer_folds_returns_and_renders_shared_arguments() {
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair("base", "[tail]", &mut seed_budget)
            .expect("seed pair fits");
        let mut digit =
            MsvcParser::new(b"P8Foo@@AA0XZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            digit.parse_datatype(Some(&mut pmt), false),
            Ok(Datatype {
                left: "base[tail] (__cdecl Foo::*".to_owned(),
                right: Some(")(void)".to_owned()),
            })
        );
        assert_eq!(pmt.logical_num(), 2);

        for (input, expected_left, expected_right) in [
            (
                b"P8Foo@@AAVBar@@XZ".as_slice(),
                "class Bar (__cdecl Foo::*",
                ")(void)",
            ),
            (b"P8Foo@@AAPAHXZ", "int * (__cdecl Foo::*", ")(void)"),
            (b"P8Foo@@AAHXZ", "int (__cdecl Foo::*", ")(void)"),
            (
                b"P8Foo@@AAHH_DZZ",
                "int (__cdecl Foo::*",
                ")(int,__int8,...)",
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid return and argument forms");
            assert_eq!(datatype.left, expected_left);
            assert_eq!(datatype.right.as_deref(), Some(expected_right));
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn member_function_pointer_uses_nullable_pmt_and_records_outer_pair_last() {
        let mut missing =
            MsvcParser::new(b"P8Foo@@AAH0Z", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            missing.parse_datatype(None, false),
            Err(ParseFailure::MissingParameterTypeReferences {
                offset: 10,
                digit: b'0',
            })
        );
        assert_eq!(missing.cursor.position(), 11);

        let mut pmt = RefArray::with_limit(4);
        let mut parser =
            MsvcParser::new(b"P8Foo@@AAH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        let datatype = parser
            .parse_datatype(Some(&mut pmt), true)
            .expect("argument pair precedes outer pair");
        assert_eq!(pmt.logical_num(), 4);
        assert_eq!(pmt.reference(0), Ok("__int8"));
        assert_eq!(pmt.reference(1), Ok(""));
        assert_eq!(pmt.reference(2), Ok(datatype.left.as_str()));
        assert_eq!(pmt.reference(3), Ok(")(__int8)"));

        let mut full = RefArray::with_limit(2);
        let mut capacity_failure =
            MsvcParser::new(b"P8Foo@@AAH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            capacity_failure.parse_datatype(Some(&mut full), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 2,
            })
        );
        assert_eq!(capacity_failure.cursor.position(), 14);
        assert_eq!(full.logical_num(), 2);
        assert_eq!(full.reference(0), Ok("__int8"));
        assert_eq!(full.reference(1), Ok(""));
        let failed_used = capacity_failure.budget.used();

        let mut baseline_pmt = RefArray::with_limit(2);
        let mut baseline =
            MsvcParser::new(b"P8Foo@@AAH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        assert!(baseline
            .parse_datatype(Some(&mut baseline_pmt), false)
            .is_ok());
        assert_eq!(failed_used, baseline.budget.used());
    }

    #[test]
    fn member_function_pointer_failures_restore_stack_and_preserve_native_side_effects() {
        for (input, expected, position) in [
            (
                b"P8".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 2 },
                2,
            ),
            (b"P8?", ParseFailure::UnexpectedEnd { offset: 3 }, 3),
            (
                b"P80",
                ParseFailure::ReferenceOutOfHighWater {
                    start: 0,
                    index: 0,
                    max: 0,
                },
                3,
            ),
            (b"P8Foo@", ParseFailure::UnexpectedEnd { offset: 6 }, 6),
            (b"P8Foo@?", ParseFailure::UnexpectedEnd { offset: 7 }, 7),
            (b"P8Foo@@", ParseFailure::UnexpectedEnd { offset: 7 }, 7),
            (b"P8Foo@@E", ParseFailure::UnexpectedEnd { offset: 8 }, 8),
            (
                b"P8Foo@@!",
                ParseFailure::InvalidModifier {
                    offset: 7,
                    found: b'!',
                },
                8,
            ),
            (b"P8Foo@@A", ParseFailure::UnexpectedEnd { offset: 8 }, 8),
            (
                b"P8Foo@@A!",
                ParseFailure::InvalidCallingConvention { found: b'!' },
                9,
            ),
            (b"P8Foo@@AA", ParseFailure::UnexpectedEnd { offset: 9 }, 9),
            (
                b"P8Foo@@AAH",
                ParseFailure::UnexpectedEnd { offset: 10 },
                10,
            ),
            (
                b"P8Foo@@AAHX!",
                ParseFailure::InvalidArgumentListTerminator {
                    offset: 11,
                    found: b'!',
                },
                12,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .stack
                .push("seed", &mut parser.budget)
                .expect("stack seed fits");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("seed"));
            if input.starts_with(b"P8Foo") {
                assert_eq!(parser.names.reference(0), Ok("Foo"));
                assert_eq!(parser.stack.reference(1), Ok("Foo"));
            }
        }

        let mut success =
            MsvcParser::new(b"P8Foo@@AAHXZ", UNDNAME_COMPLETE).expect("input within limit");
        success
            .stack
            .push("seed", &mut success.budget)
            .expect("stack seed fits");
        assert!(success.parse_datatype(None, false).is_ok());
        assert_eq!(success.stack.logical_num(), 1);
        assert_eq!(success.stack.reference(1), Ok("Foo"));
    }

    #[test]
    fn member_function_pointer_restores_stack_after_final_render_budget_failure() {
        let input = b"P8Foo@@AAHXZ";
        let mut baseline = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        assert!(baseline.parse_datatype(None, false).is_ok());
        let final_used = baseline.budget.used();

        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        parser.budget = AttemptBudget::with_limit(final_used - 1);
        parser
            .stack
            .push("seed", &mut parser.budget)
            .expect("stack seed fits");
        assert!(matches!(
            parser.parse_datatype(None, false),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 1);
        assert_eq!(parser.stack.reference(0), Ok("seed"));
        assert_eq!(parser.stack.reference(1), Ok("Foo"));
        assert_eq!(parser.names.reference(0), Ok("Foo"));
    }

    #[test]
    fn p8_dispatch_is_p_only_and_sibling_digits_stay_consumed_unsupported() {
        for (input, introducer, found) in
            [(b"Q8tail".as_slice(), "Q", b'8'), (b"P1tail", "P", b'1')]
        {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_datatype(None, false),
                Err(ParseFailure::UnsupportedDatatypeForm {
                    offset: 1,
                    found,
                    introducer,
                })
            );
            assert_eq!(parser.cursor.position(), 2);
        }
    }

    #[test]
    fn member_function_pointer_nested_returns_obey_depth_and_render_exactly() {
        let mut nested = MsvcParser::new(b"P8Foo@@AAP8Bar@@AAHXZXZ", UNDNAME_COMPLETE)
            .expect("input within limit");
        assert_eq!(
            nested.parse_datatype(None, false),
            Ok(Datatype {
                left: "int (__cdecl Bar::*)(void) (__cdecl Foo::*".to_owned(),
                right: Some(")(void)".to_owned()),
            })
        );
        assert_eq!(nested.depth, 0);
        assert_eq!(nested.stack.logical_num(), 0);

        let exact_input = format!(
            "{}H{}",
            "P8Foo@@AA".repeat(MAX_NESTING_DEPTH - 1),
            "XZ".repeat(MAX_NESTING_DEPTH - 1)
        );
        let mut exact =
            MsvcParser::new(exact_input.as_bytes(), UNDNAME_COMPLETE).expect("input within limit");
        assert!(exact.parse_datatype(None, false).is_ok());
        assert_eq!(exact.depth, 0);
        assert_eq!(exact.stack.logical_num(), 0);

        let over_input = format!(
            "{}H{}",
            "P8Foo@@AA".repeat(MAX_NESTING_DEPTH),
            "XZ".repeat(MAX_NESTING_DEPTH)
        );
        let mut over =
            MsvcParser::new(over_input.as_bytes(), UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            over.parse_datatype(None, false),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(over.cursor.position(), MAX_NESTING_DEPTH * 9);
        assert_eq!(over.depth, 0);
        assert_eq!(over.stack.logical_num(), 0);
    }

    #[test]
    fn member_function_pointer_class_and_args_share_cumulative_budget() {
        let component = "x".repeat(300);
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair(&component, "", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser =
            MsvcParser::new(b"P80@AAH00XZ", UNDNAME_COMPLETE).expect("input within limit");
        parser.budget = AttemptBudget::with_limit(1_000);
        parser
            .names
            .push(&component, &mut parser.budget)
            .expect("name seed fits");

        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), false),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 1_203,
                limit: 1_000,
            })
        );
        assert_eq!(parser.cursor.position(), 8);
        assert_eq!(parser.cursor.peek(0), Some(b'0'));
        assert_eq!(parser.budget.used(), 903);
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(parser.stack.reference(0), Ok(component.as_str()));
        assert_eq!(pmt.logical_num(), 2);
    }

    #[test]
    fn standalone_function_datatypes_render_export_order_and_cursor_exactly() {
        for (input, expected) in [
            (b"$$A6AHXZ".as_slice(), "int __cdecl (void)"),
            (b"$$A6BHXZ", "int __cdecl __dll_export (void)"),
            (b"$$A6KHXZ", "int (void)"),
            (b"$$A6LHXZ", "int __dll_export (void)"),
            (b"$$A6APAHXZ", "int * __cdecl (void)"),
            (b"$$A6AVFoo@@XZ", "class Foo __cdecl (void)"),
            (b"$$A6AHH_DZZ", "int __cdecl (int,__int8,...)"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid standalone function datatype");
            assert_eq!(datatype.left, expected);
            assert_eq!(datatype.right, None);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn standalone_function_flags_and_return_fragment_order_match_source() {
        for (input, flags, expected) in [
            (
                b"$$A6AHXZ".as_slice(),
                UNDNAME_NO_ALLOCATION_LANGUAGE,
                "int __cdecl (void)",
            ),
            (
                b"$$A6BHXZ",
                UNDNAME_NO_LEADING_UNDERSCORES,
                "int cdecl dll_export (void)",
            ),
            (
                &[b'$', b'$', b'A', b'6', 0xff, b'H', b'X', b'Z'],
                UNDNAME_NO_MS_KEYWORDS,
                "int (void)",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid flagged form");
            assert_eq!(datatype.left, expected);
            assert_eq!(datatype.right, None);
            assert_eq!(parser.cursor.position(), input.len());
        }

        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair("Ret", "[4]", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser =
            MsvcParser::new(b"$$A6A0XZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), false),
            Ok(Datatype {
                left: "Ret__cdecl (void)[4]".to_owned(),
                right: None
            })
        );
        assert_eq!(pmt.logical_num(), 2);
    }

    #[test]
    fn standalone_function_uses_nullable_pmt_and_records_empty_right_outer_pair_last() {
        let mut missing =
            MsvcParser::new(b"$$A6AH0Z", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            missing.parse_datatype(None, false),
            Err(ParseFailure::MissingParameterTypeReferences {
                offset: 6,
                digit: b'0'
            })
        );
        assert_eq!(missing.cursor.position(), 7);

        let mut pmt = RefArray::with_limit(4);
        let mut parser =
            MsvcParser::new(b"$$A6AH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        let datatype = parser
            .parse_datatype(Some(&mut pmt), true)
            .expect("pairs fit");
        assert_eq!(pmt.logical_num(), 4);
        assert_eq!(pmt.reference(0), Ok("__int8"));
        assert_eq!(pmt.reference(1), Ok(""));
        assert_eq!(pmt.reference(2), Ok(datatype.left.as_str()));
        assert_eq!(pmt.reference(3), Ok(""));

        let mut full = RefArray::with_limit(2);
        let mut failure =
            MsvcParser::new(b"$$A6AH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            failure.parse_datatype(Some(&mut full), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 2
            })
        );
        assert_eq!(failure.cursor.position(), 10);
        assert_eq!(full.logical_num(), 2);
        assert_eq!(full.reference(0), Ok("__int8"));
        assert_eq!(full.reference(1), Ok(""));
    }

    #[test]
    fn standalone_function_dispatch_truncations_and_stack_restore_are_exact() {
        for (input, expected, position) in [
            (
                b"$$A".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 3 },
                3,
            ),
            (
                b"$$AX",
                ParseFailure::UnsupportedDatatypeForm {
                    offset: 3,
                    found: b'X',
                    introducer: "$$A",
                },
                3,
            ),
            (b"$$A6", ParseFailure::UnexpectedEnd { offset: 4 }, 4),
            (b"$$A6A", ParseFailure::UnexpectedEnd { offset: 5 }, 5),
            (b"$$A6AH", ParseFailure::UnexpectedEnd { offset: 6 }, 6),
            (
                b"$$A6AHX!",
                ParseFailure::InvalidArgumentListTerminator {
                    offset: 7,
                    found: b'!',
                },
                8,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .stack
                .push("seed", &mut parser.budget)
                .expect("stack seed fits");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("seed"));
            assert_eq!(parser.depth, 0);
        }
    }

    #[test]
    fn standalone_function_nested_return_and_argument_backrefs_are_bounded() {
        let mut nested =
            MsvcParser::new(b"$$A6A$$A6AHXZXZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            nested.parse_datatype(None, false),
            Ok(Datatype {
                left: "int __cdecl (void) __cdecl (void)".to_owned(),
                right: None,
            })
        );
        assert_eq!(nested.depth, 0);
        assert_eq!(nested.stack.logical_num(), 0);

        let component = "x".repeat(300);
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair(&component, "", &mut seed_budget)
            .expect("seed pair fits");
        let mut bounded =
            MsvcParser::new(b"$$A6AH00XZ", UNDNAME_COMPLETE).expect("input within limit");
        bounded.budget = AttemptBudget::with_limit(1_000);
        assert_eq!(
            bounded.parse_datatype(Some(&mut pmt), false),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 1_203,
                limit: 1_000,
            })
        );
        assert_eq!(bounded.cursor.position(), 8);
        assert_eq!(bounded.cursor.peek(0), Some(b'X'));
        assert_eq!(bounded.budget.used(), 903);
        assert_eq!(bounded.stack.logical_num(), 0);
        assert_eq!(pmt.logical_num(), 2);
    }

    #[test]
    fn function_pointer_datatypes_render_exact_left_right_and_cursor() {
        for (input, expected_left, expected_right) in [
            (b"P6AHXZ".as_slice(), "int (__cdecl*", ")(void)"),
            (b"Q6AHXZ", "int (__cdecl*const", ")(void)"),
            (b"P6GHHXZ", "int (__stdcall*", ")(int)"),
            (b"Q6IHHXZ", "int (__fastcall*const", ")(int)"),
            (b"P6AHH_DZZ", "int (__cdecl*", ")(int,__int8,...)"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid function pointer datatype");
            assert_eq!(datatype.left, expected_left);
            assert_eq!(datatype.right.as_deref(), Some(expected_right));
            assert_eq!(
                format!("{}{}", datatype.left, expected_right),
                format!("{expected_left}{expected_right}")
            );
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn function_pointer_calling_convention_flags_match_source_quirks() {
        for (input, flags, expected_left) in [
            (
                b"P6AHXZ".as_slice(),
                UNDNAME_NO_ALLOCATION_LANGUAGE,
                "int (__cdecl*",
            ),
            (b"P6BHXZ", UNDNAME_COMPLETE, "int (__cdecl*"),
            (b"P6KHXZ", UNDNAME_COMPLETE, "int (*"),
            (b"Q6LHXZ", UNDNAME_COMPLETE, "int (*const"),
            (b"P6AHXZ", UNDNAME_NO_LEADING_UNDERSCORES, "int (cdecl*"),
            (
                &[b'P', b'6', 0xff, b'H', b'X', b'Z'],
                UNDNAME_NO_MS_KEYWORDS,
                "int (*",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("calling convention form is accepted");
            assert_eq!(datatype.left, expected_left);
            assert_eq!(datatype.right.as_deref(), Some(")(void)"));
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn function_pointer_return_folds_right_and_preserves_recursive_forms() {
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair("base", "[tail]", &mut seed_budget)
            .expect("seed pair fits");
        let mut digit = MsvcParser::new(b"P6A0XZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            digit.parse_datatype(Some(&mut pmt), false),
            Ok(Datatype {
                left: "base[tail] (__cdecl*".to_owned(),
                right: Some(")(void)".to_owned()),
            })
        );
        assert_eq!(pmt.logical_num(), 2, "return parsing must not add a pair");

        for (input, expected_left) in [
            (b"P6AVFoo@@XZ".as_slice(), "class Foo (__cdecl*"),
            (b"P6APAHXZ", "int * (__cdecl*"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            let datatype = parser
                .parse_datatype(None, false)
                .expect("valid return type");
            assert_eq!(datatype.left, expected_left);
            assert_eq!(datatype.right.as_deref(), Some(")(void)"));
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn function_pointer_uses_nullable_shared_pmt_and_records_outer_pair_last() {
        let mut missing = MsvcParser::new(b"P6AH0Z", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            missing.parse_datatype(None, false),
            Err(ParseFailure::MissingParameterTypeReferences {
                offset: 4,
                digit: b'0',
            })
        );
        assert_eq!(missing.cursor.position(), 5);

        let mut pmt = RefArray::with_limit(4);
        let mut parser =
            MsvcParser::new(b"P6AH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        let datatype = parser
            .parse_datatype(Some(&mut pmt), true)
            .expect("argument and outer pairs fit");
        assert_eq!(pmt.logical_num(), 4);
        assert_eq!(pmt.reference(0), Ok("__int8"));
        assert_eq!(pmt.reference(1), Ok(""));
        assert_eq!(pmt.reference(2), Ok(datatype.left.as_str()));
        assert_eq!(pmt.reference(3), Ok(")(__int8)"));

        let mut full = RefArray::with_limit(2);
        let mut parser =
            MsvcParser::new(b"P6AH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            parser.parse_datatype(Some(&mut full), true),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 4,
                limit: 2,
            })
        );
        assert_eq!(parser.cursor.position(), 8);
        assert_eq!(full.logical_num(), 2);
        assert_eq!(full.reference(0), Ok("__int8"));
        assert_eq!(full.reference(1), Ok(""));

        let failed_used = parser.budget.used();
        let mut baseline_pmt = RefArray::with_limit(2);
        let mut baseline =
            MsvcParser::new(b"P6AH_DXZ", UNDNAME_COMPLETE).expect("input within limit");
        assert!(baseline
            .parse_datatype(Some(&mut baseline_pmt), false)
            .is_ok());
        assert_eq!(
            failed_used,
            baseline.budget.used(),
            "rejected outer pair must not be charged"
        );
    }

    #[test]
    fn function_pointer_failures_consume_exactly_and_restore_stack() {
        for (input, expected, position) in [
            (
                b"P6".as_slice(),
                ParseFailure::UnexpectedEnd { offset: 2 },
                2,
            ),
            (b"P6A", ParseFailure::UnexpectedEnd { offset: 3 }, 3),
            (
                b"P6!HXZ",
                ParseFailure::InvalidCallingConvention { found: b'!' },
                3,
            ),
            (
                b"P6AHX!",
                ParseFailure::InvalidArgumentListTerminator {
                    offset: 5,
                    found: b'!',
                },
                6,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .stack
                .push("seed", &mut parser.budget)
                .expect("stack seed fits");
            assert_eq!(parser.parse_datatype(None, false), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("seed"));
        }
    }

    #[test]
    fn function_pointer_arguments_share_the_cumulative_backreference_budget() {
        let component = "x".repeat(300);
        let mut seed_budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair(&component, "", &mut seed_budget)
            .expect("seed pair fits");
        let mut parser =
            MsvcParser::new(b"P6AH00XZ", UNDNAME_COMPLETE).expect("input within limit");
        parser.budget = AttemptBudget::with_limit(1_000);

        assert_eq!(
            parser.parse_datatype(Some(&mut pmt), false),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 1_203,
                limit: 1_000,
            })
        );
        assert_eq!(parser.cursor.position(), 6);
        assert_eq!(parser.cursor.peek(0), Some(b'X'));
        assert_eq!(parser.budget.used(), 903);
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(pmt.logical_num(), 2);
    }

    #[test]
    fn function_pointer_restores_stack_and_obeys_recursive_depth_guard() {
        for input in [b"P6AVFoo@@XZ".as_slice(), b"P6AVFoo@?XZ"] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            parser
                .stack
                .push("seed", &mut parser.budget)
                .expect("stack seed fits");
            let _ = parser.parse_datatype(None, false);
            assert_eq!(parser.depth, 0);
            assert_eq!(parser.stack.logical_num(), 1);
            assert_eq!(parser.stack.reference(0), Ok("seed"));
            assert_eq!(parser.stack.reference(1), Ok("Foo"));
        }

        let exact_input = format!(
            "{}H{}",
            "P6A".repeat(MAX_NESTING_DEPTH - 1),
            "XZ".repeat(MAX_NESTING_DEPTH - 1)
        );
        let mut exact =
            MsvcParser::new(exact_input.as_bytes(), UNDNAME_COMPLETE).expect("input within limit");
        assert!(exact.parse_datatype(None, false).is_ok());
        assert_eq!(exact.depth, 0);

        let over_input = format!(
            "{}H{}",
            "P6A".repeat(MAX_NESTING_DEPTH),
            "XZ".repeat(MAX_NESTING_DEPTH)
        );
        let mut over =
            MsvcParser::new(over_input.as_bytes(), UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            over.parse_datatype(None, false),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(over.cursor.position(), MAX_NESTING_DEPTH * 3);
        assert_eq!(over.depth, 0);
    }

    #[test]
    fn datatype_depth_guard_accepts_limit_rejects_one_over_and_restores_state() {
        let exact_input = format!("{}H", "PA".repeat(MAX_NESTING_DEPTH - 1));
        let mut exact =
            MsvcParser::new(exact_input.as_bytes(), UNDNAME_COMPLETE).expect("input within limit");
        assert!(exact.parse_datatype(None, false).is_ok());
        assert_eq!(exact.cursor.position(), exact_input.len());
        assert_eq!(exact.depth, 0);
        assert_eq!(exact.stack.logical_num(), 0);

        let over_input = format!("{}H", "PA".repeat(MAX_NESTING_DEPTH));
        let mut over =
            MsvcParser::new(over_input.as_bytes(), UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            over.parse_datatype(None, false),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(over.cursor.position(), MAX_NESTING_DEPTH * 2);
        assert_eq!(over.cursor.peek(0), Some(b'H'));
        assert_eq!(over.depth, 0);
        assert_eq!(over.stack.logical_num(), 0);

        let mut failed =
            MsvcParser::new(b"PAVFoo@?", UNDNAME_COMPLETE).expect("input within limit");
        failed
            .stack
            .push("seed", &mut failed.budget)
            .expect("stack seed fits");
        assert_eq!(
            failed.parse_datatype(None, false),
            Err(ParseFailure::UnexpectedEnd { offset: 8 })
        );
        assert_eq!(failed.depth, 0);
        assert_eq!(failed.stack.logical_num(), 1);
        assert_eq!(failed.stack.reference(0), Ok("seed"));

        let mut succeeded =
            MsvcParser::new(b"PAVFoo@@", UNDNAME_COMPLETE).expect("input within limit");
        succeeded
            .stack
            .push("seed", &mut succeeded.budget)
            .expect("stack seed fits");
        assert_eq!(
            succeeded.parse_datatype(None, false),
            Ok(Datatype {
                left: "class Foo *".to_owned(),
                right: None,
            })
        );
        assert_eq!(succeeded.depth, 0);
        assert_eq!(succeeded.stack.logical_num(), 1);
        assert_eq!(succeeded.stack.reference(0), Ok("seed"));
        assert_eq!(succeeded.stack.reference(1), Ok("Foo"));
    }

    #[test]
    fn ordinary_datatype_oracle_covers_every_byte_and_never_adds_pmt() {
        let mut budget = AttemptBudget::new();
        for byte in 0..=u8::MAX {
            let expected_left = match byte {
                b'C' => Some("signed char"),
                b'D' => Some("char"),
                b'E' => Some("unsigned char"),
                b'F' => Some("short"),
                b'G' => Some("unsigned short"),
                b'H' => Some("int"),
                b'I' => Some("unsigned int"),
                b'J' => Some("long"),
                b'K' => Some("unsigned long"),
                b'M' => Some("float"),
                b'N' => Some("double"),
                b'O' => Some("long double"),
                b'X' => Some("void"),
                b'Z' => Some("..."),
                _ => None,
            };
            let input = [byte];
            let mut cursor = Cursor::new(&input);
            let mut pmt = RefArray::with_limit(4);

            if let Some(left) = expected_left {
                assert_eq!(
                    parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
                    Ok(Datatype {
                        left: left.to_owned(),
                        right: None,
                    }),
                    "byte {byte:#04x}"
                );
                assert!(matches!(
                    pmt.reference(0),
                    Err(ParseFailure::ReferenceOutOfHighWater { max: 0, .. })
                ));
            } else if matches!(byte, b'_' | b'$') {
                assert_eq!(
                    parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
                    Err(ParseFailure::UnexpectedEnd { offset: 1 })
                );
            } else if byte.is_ascii_digit() {
                assert_eq!(
                    parse_datatype(&mut cursor, None, false, &mut budget),
                    Err(ParseFailure::MissingParameterTypeReferences {
                        offset: 0,
                        digit: byte,
                    })
                );
            } else {
                assert_eq!(
                    parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
                    Err(ParseFailure::InvalidDatatypeCode {
                        offset: 0,
                        found: byte,
                    }),
                    "byte {byte:#04x}"
                );
            }
            assert_eq!(cursor.position(), 1, "byte {byte:#04x}");
        }
    }

    #[test]
    fn extended_datatypes_map_exactly_and_add_empty_right_pairs_only_for_arguments() {
        let mut budget = AttemptBudget::new();
        for (code, left) in [
            (b'D', "__int8"),
            (b'E', "unsigned __int8"),
            (b'F', "__int16"),
            (b'G', "unsigned __int16"),
            (b'H', "__int32"),
            (b'I', "unsigned __int32"),
            (b'J', "__int64"),
            (b'K', "unsigned __int64"),
            (b'L', "__int128"),
            (b'M', "unsigned __int128"),
            (b'N', "bool"),
            (b'W', "wchar_t"),
        ] {
            let input = [b'_', code, b'x'];
            let expected = Datatype {
                left: left.to_owned(),
                right: None,
            };

            let mut pmt = RefArray::with_limit(2);
            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
                Ok(expected.clone())
            );
            assert_eq!(cursor.position(), 2);
            assert_eq!(pmt.reference(0), Ok(left));
            assert_eq!(pmt.reference(1), Ok(""));

            let mut pmt = RefArray::with_limit(2);
            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, Some(&mut pmt), false, &mut budget),
                Ok(expected.clone())
            );
            assert_eq!(cursor.position(), 2);
            assert!(matches!(
                pmt.reference(0),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 0, .. })
            ));

            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, None, true, &mut budget),
                Ok(expected)
            );
            assert_eq!(cursor.position(), 2);
        }
    }

    #[test]
    fn digit_datatypes_resolve_pairs_and_preserve_missing_right_as_none() {
        let mut budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(4);
        for value in ["left0", "right0", "left1", "right1"] {
            pmt.push(value, &mut budget).expect("within limit");
        }
        for (digit, left, right) in [(b'0', "left0", "right0"), (b'1', "left1", "right1")] {
            let input = [digit, b'x'];
            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
                Ok(Datatype {
                    left: left.to_owned(),
                    right: Some(right.to_owned())
                })
            );
            assert_eq!(cursor.position(), 1);
        }

        let mut left_only = RefArray::with_limit(1);
        left_only.push("left", &mut budget).expect("within limit");
        let mut cursor = Cursor::new(b"0x");
        assert_eq!(
            parse_datatype(&mut cursor, Some(&mut left_only), false, &mut budget),
            Ok(Datatype {
                left: "left".to_owned(),
                right: None
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn digit_datatype_errors_after_consumption_for_missing_table_or_left() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"1x");
        assert_eq!(
            parse_datatype(&mut cursor, None, true, &mut budget),
            Err(ParseFailure::MissingParameterTypeReferences {
                offset: 0,
                digit: b'1'
            })
        );
        assert_eq!(cursor.position(), 1);

        let mut pmt = RefArray::with_limit(2);
        pmt.push("left0", &mut budget).expect("within limit");
        pmt.push("right0", &mut budget).expect("within limit");
        let mut cursor = Cursor::new(b"1x");
        assert_eq!(
            parse_datatype(&mut cursor, Some(&mut pmt), false, &mut budget),
            Err(ParseFailure::ReferenceOutOfHighWater {
                start: 0,
                index: 2,
                max: 2
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn digit_datatype_reads_historical_high_water_after_rollback() {
        let mut budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push_pair("left", "right", &mut budget)
            .expect("within limit");
        pmt.restore_num(0).expect("historical position");
        let mut cursor = Cursor::new(b"0x");

        assert_eq!(
            parse_datatype(&mut cursor, Some(&mut pmt), false, &mut budget),
            Ok(Datatype {
                left: "left".to_owned(),
                right: Some("right".to_owned())
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn datatype_invalid_and_eof_inputs_have_exact_consumption() {
        let mut budget = AttemptBudget::new();
        let mut empty = Cursor::new(b"");
        assert_eq!(
            parse_datatype(&mut empty, None, false, &mut budget),
            Err(ParseFailure::UnexpectedEnd { offset: 0 })
        );
        assert_eq!(empty.position(), 0);

        for byte in [b'!', 0x80, u8::MAX] {
            let input = [byte, b'x'];
            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, None, false, &mut budget),
                Err(ParseFailure::InvalidDatatypeCode {
                    offset: 0,
                    found: byte
                })
            );
            assert_eq!(cursor.position(), 1);
        }

        for (input, found) in [(b"_!x".as_slice(), b'!'), (b"_Xx", b'X')] {
            let mut invalid_extended = Cursor::new(input);
            assert_eq!(
                parse_datatype(&mut invalid_extended, None, false, &mut budget),
                Err(ParseFailure::InvalidDatatypeCode { offset: 1, found })
            );
            assert_eq!(invalid_extended.position(), 2);
        }

        let mut lone_underscore = Cursor::new(b"_");
        assert_eq!(
            parse_datatype(&mut lone_underscore, None, false, &mut budget),
            Err(ParseFailure::UnexpectedEnd { offset: 1 })
        );
        assert_eq!(lone_underscore.position(), 1);
    }

    #[test]
    fn datatype_pair_capacity_failure_is_atomic_after_consumption() {
        let mut budget = AttemptBudget::new();
        let mut pmt = RefArray::with_limit(2);
        pmt.push("seed", &mut budget).expect("within limit");
        let mut cursor = Cursor::new(b"_Dx");

        assert_eq!(
            parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 3,
                limit: 2
            })
        );
        assert_eq!(cursor.position(), 2);
        assert_eq!(pmt.reference(0), Ok("seed"));
        assert!(matches!(
            pmt.reference(1),
            Err(ParseFailure::ReferenceOutOfHighWater { max: 1, .. })
        ));
    }

    #[test]
    fn dollar_numeric_datatypes_render_numbers_exactly_and_consume_all_input() {
        let mut budget = AttemptBudget::new();
        for (input, expected) in [
            (b"$00".as_slice(), "1"),
            (b"$0?0", "-1"),
            (b"$0BA@", "16"),
            (b"$D0", "`template-parameter1'"),
            (b"$D?0", "`template-parameter-1'"),
            (b"$DBA@", "`template-parameter16'"),
            (b"$F00", "{1,1}"),
            (b"$F?0?1", "{-1,-2}"),
            (b"$FBA@P@", "{16,15}"),
            (b"$G000", "{1,1,1}"),
            (b"$G?0?1?2", "{-1,-2,-3}"),
            (b"$GBA@P@BC@", "{16,15,18}"),
            (b"$Q0", "`non-type-template-parameter1'"),
            (b"$Q?0", "`non-type-template-parameter-1'"),
            (b"$QBA@", "`non-type-template-parameter16'"),
        ] {
            let mut cursor = Cursor::new(input);
            assert_eq!(
                parse_datatype(&mut cursor, None, false, &mut budget),
                Ok(Datatype {
                    left: expected.to_owned(),
                    right: None,
                }),
                "input {:?}",
                String::from_utf8_lossy(input)
            );
            assert_eq!(cursor.position(), input.len());
        }
    }

    #[test]
    fn dollar_nullptr_datatype_consumes_both_dollars_and_t() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"$$Ttail");

        assert_eq!(
            parse_datatype(&mut cursor, None, false, &mut budget),
            Ok(Datatype {
                left: "std::nullptr_t".to_owned(),
                right: None,
            })
        );
        assert_eq!(cursor.position(), 3);
    }

    #[test]
    fn dollar_datatypes_add_atomic_empty_right_pairs_only_for_arguments() {
        let mut budget = AttemptBudget::new();
        for (input, expected, consumed) in [
            (b"$00".as_slice(), "1", 3),
            (b"$D0", "`template-parameter1'", 3),
            (b"$F00", "{1,1}", 4),
            (b"$G000", "{1,1,1}", 5),
            (b"$Q0", "`non-type-template-parameter1'", 3),
            (b"$$T", "std::nullptr_t", 3),
        ] {
            let mut pmt = RefArray::with_limit(2);
            let mut cursor = Cursor::new(input);
            assert!(parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget).is_ok());
            assert_eq!(cursor.position(), consumed);
            assert_eq!(pmt.reference(0), Ok(expected));
            assert_eq!(pmt.reference(1), Ok(""));

            let mut pmt = RefArray::with_limit(2);
            let mut cursor = Cursor::new(input);
            assert!(parse_datatype(&mut cursor, Some(&mut pmt), false, &mut budget).is_ok());
            assert!(matches!(
                pmt.reference(0),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 0, .. })
            ));

            let mut cursor = Cursor::new(input);
            assert!(parse_datatype(&mut cursor, None, true, &mut budget).is_ok());
            assert_eq!(cursor.position(), consumed);
        }
    }

    #[test]
    fn dollar_datatype_pair_capacity_failures_leave_pmt_unchanged_after_full_parse() {
        let mut budget = AttemptBudget::new();
        for input in [b"$00".as_slice(), b"$D0", b"$F00", b"$G000", b"$Q0", b"$$T"] {
            let mut pmt = RefArray::with_limit(2);
            pmt.push("seed", &mut budget).expect("within limit");
            let mut cursor = Cursor::new(input);

            assert_eq!(
                parse_datatype(&mut cursor, Some(&mut pmt), true, &mut budget),
                Err(ParseFailure::ReferenceLimitExceeded {
                    attempted: 3,
                    limit: 2,
                })
            );
            assert_eq!(cursor.position(), input.len());
            assert_eq!(pmt.reference(0), Ok("seed"));
            assert!(matches!(
                pmt.reference(1),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 1, .. })
            ));
        }
    }

    #[test]
    fn truncated_dollar_datatypes_stop_at_each_exact_boundary() {
        let mut budget = AttemptBudget::new();
        for (input, expected) in [
            (b"$".as_slice(), ParseFailure::UnexpectedEnd { offset: 1 }),
            (
                b"$D",
                ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: None,
                },
            ),
            (
                b"$F0",
                ParseFailure::InvalidNumberStart {
                    offset: 3,
                    found: None,
                },
            ),
            (
                b"$G00",
                ParseFailure::InvalidNumberStart {
                    offset: 4,
                    found: None,
                },
            ),
            (b"$$", ParseFailure::UnexpectedEnd { offset: 2 }),
        ] {
            let mut cursor = Cursor::new(input);
            assert_eq!(
                parse_datatype(&mut cursor, None, false, &mut budget),
                Err(expected)
            );
            assert_eq!(cursor.position(), input.len());
        }
    }

    #[test]
    fn malformed_supported_dollar_forms_preserve_number_errors_and_partial_consumption() {
        let mut budget = AttemptBudget::new();
        for (input, expected, position) in [
            (
                b"$0!".as_slice(),
                ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: Some(b'!'),
                },
                2,
            ),
            (
                b"$D!",
                ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: Some(b'!'),
                },
                2,
            ),
            (
                b"$F0!",
                ParseFailure::InvalidNumberStart {
                    offset: 3,
                    found: Some(b'!'),
                },
                3,
            ),
            (
                b"$G00!",
                ParseFailure::InvalidNumberStart {
                    offset: 4,
                    found: Some(b'!'),
                },
                4,
            ),
            (
                b"$Q!",
                ParseFailure::InvalidNumberStart {
                    offset: 2,
                    found: Some(b'!'),
                },
                2,
            ),
            (
                b"$DB!",
                ParseFailure::MissingNumberTerminator {
                    offset: 3,
                    found: Some(b'!'),
                },
                3,
            ),
        ] {
            let mut cursor = Cursor::new(input);
            assert_eq!(
                parse_datatype(&mut cursor, None, false, &mut budget),
                Err(expected)
            );
            assert_eq!(cursor.position(), position);
            assert_eq!(cursor.peek(0), Some(b'!'));
        }
    }

    #[test]
    fn unsupported_outer_dollar_subtypes_are_consumed_with_typed_context() {
        let mut budget = AttemptBudget::new();
        for found in [b'1', b'X', 0x80, u8::MAX] {
            let input = [b'$', found, b'z'];
            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, None, false, &mut budget),
                Err(ParseFailure::UnsupportedDatatypeForm {
                    offset: 1,
                    found,
                    introducer: "$",
                })
            );
            assert_eq!(cursor.position(), 2);
        }
    }

    #[test]
    fn unsupported_inner_dollar_subtypes_remain_unconsumed_with_typed_context() {
        let mut budget = AttemptBudget::new();
        for found in [b'A', b'B', b'C', b'Q', b'X', 0x80, u8::MAX] {
            let input = [b'$', b'$', found, b'z'];
            let mut cursor = Cursor::new(&input);
            assert_eq!(
                parse_datatype(&mut cursor, None, false, &mut budget),
                Err(ParseFailure::UnsupportedDatatypeForm {
                    offset: 2,
                    found,
                    introducer: "$$",
                })
            );
            assert_eq!(cursor.position(), 2);
            assert_eq!(cursor.peek(0), Some(found));
        }
    }

    #[test]
    fn literal_string_is_stored_and_consumes_its_terminator() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"Ab9_$<>@tail");
        let mut names = RefArray::with_limit(4);

        assert_eq!(
            parse_literal_string(&mut cursor, &mut names, &mut budget),
            Ok("Ab9_$<>".to_owned())
        );
        assert_eq!(cursor.position(), 8);
        assert_eq!(names.reference(0), Ok("Ab9_$<>"));
    }

    #[test]
    fn literal_byte_classifier_matches_c_for_every_byte() {
        for byte in 0..=u8::MAX {
            let expected = matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'$' | b'<' | b'>'
            );
            assert_eq!(is_literal_byte(byte), expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn invalid_literal_inputs_stop_before_the_offending_byte() {
        let mut budget = AttemptBudget::new();
        for (input, offset, found) in [
            (b"@".as_slice(), 0, Some(b'@')),
            (b"!".as_slice(), 0, Some(b'!')),
            (b"Ab!".as_slice(), 2, Some(b'!')),
            (b"Ab".as_slice(), 2, None),
            ([0xff].as_slice(), 0, Some(0xff)),
        ] {
            let mut cursor = Cursor::new(input);
            let mut names = RefArray::with_limit(4);
            assert_eq!(
                parse_literal_string(&mut cursor, &mut names, &mut budget),
                Err(ParseFailure::InvalidLiteral { offset, found })
            );
            assert_eq!(cursor.position(), offset);
            assert!(matches!(
                names.reference(0),
                Err(ParseFailure::ReferenceOutOfHighWater { max: 0, .. })
            ));
        }
    }

    #[test]
    fn literal_push_after_rollback_overwrites_historical_slot() {
        let mut budget = AttemptBudget::new();
        let mut names = RefArray::with_limit(4);
        names.push("A", &mut budget).expect("within limit");
        names.push("B", &mut budget).expect("within limit");
        names.restore_num(1).expect("historical position");
        let mut cursor = Cursor::new(b"C@tail");

        assert_eq!(
            parse_literal_string(&mut cursor, &mut names, &mut budget),
            Ok("C".to_owned())
        );
        assert_eq!(names.reference(1), Ok("C"));
        names.restore_num(2).expect("high-water remains two");
    }

    #[test]
    fn literal_capacity_failure_consumes_input_but_does_not_mutate_refs() {
        let mut budget = AttemptBudget::new();
        let mut names = RefArray::with_limit(0);
        let mut cursor = Cursor::new(b"A@tail");

        assert_eq!(
            parse_literal_string(&mut cursor, &mut names, &mut budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(cursor.position(), 2);
        assert!(matches!(
            names.reference(0),
            Err(ParseFailure::ReferenceOutOfHighWater { max: 0, .. })
        ));
    }

    fn assert_modifier(
        input: &[u8],
        flags: u16,
        expected_qualifier: Option<&'static str>,
        expected_pointer_modifier: Option<&'static str>,
        expected_position: usize,
    ) {
        let mut cursor = Cursor::new(input);

        assert_eq!(
            parse_modifier(&mut cursor, flags),
            Ok(Modifier {
                qualifier: expected_qualifier,
                pointer_modifier: expected_pointer_modifier,
            })
        );
        assert_eq!(cursor.position(), expected_position);
    }

    #[test]
    fn modifier_codes_map_qualifiers_and_consume_exactly_one_byte() {
        for (code, qualifier) in [
            (b'A', None),
            (b'B', Some("const")),
            (b'C', Some("volatile")),
            (b'D', Some("const volatile")),
        ] {
            assert_modifier(&[code, b'x'], UNDNAME_COMPLETE, qualifier, None, 1);
        }
    }

    #[test]
    fn leading_e_selects_pointer_keyword_according_to_flags() {
        assert_modifier(b"EAx", UNDNAME_COMPLETE, None, Some("__ptr64"), 2);
        assert_modifier(
            b"EAx",
            UNDNAME_NO_LEADING_UNDERSCORES,
            None,
            Some("ptr64"),
            2,
        );
        assert_modifier(b"EAx", UNDNAME_NO_MS_KEYWORDS, None, None, 2);
    }

    #[test]
    fn wrapper_flags_consume_e_and_suppress_pointer_keyword() {
        assert_modifier(b"EAx", VMP_DEMANGLE_FLAGS, None, None, 2);
    }

    #[test]
    fn invalid_modifier_is_consumed_and_reports_byte_and_offset() {
        let mut cursor = Cursor::new(b"!x");
        assert_eq!(
            parse_modifier(&mut cursor, UNDNAME_COMPLETE),
            Err(ParseFailure::InvalidModifier {
                offset: 0,
                found: b'!',
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn invalid_modifier_after_e_is_consumed_at_modifier_offset() {
        let mut cursor = Cursor::new(b"E!x");
        assert_eq!(
            parse_modifier(&mut cursor, UNDNAME_COMPLETE),
            Err(ParseFailure::InvalidModifier {
                offset: 1,
                found: b'!',
            })
        );
        assert_eq!(cursor.position(), 2);
    }

    #[test]
    fn modifier_eof_does_not_advance_past_boundary() {
        let mut empty = Cursor::new(b"");
        assert_eq!(
            parse_modifier(&mut empty, UNDNAME_COMPLETE),
            Err(ParseFailure::UnexpectedEnd { offset: 0 })
        );
        assert_eq!(empty.position(), 0);

        let mut lone_e = Cursor::new(b"E");
        assert_eq!(
            parse_modifier(&mut lone_e, UNDNAME_COMPLETE),
            Err(ParseFailure::UnexpectedEnd { offset: 1 })
        );
        assert_eq!(lone_e.position(), 1);
    }

    #[test]
    fn high_bit_invalid_modifier_is_consumed_as_an_unsigned_byte() {
        let mut cursor = Cursor::new(&[0xff, b'x']);
        assert_eq!(
            parse_modifier(&mut cursor, UNDNAME_COMPLETE),
            Err(ParseFailure::InvalidModifier {
                offset: 0,
                found: 0xff,
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    fn assert_number(input: &[u8], expected: &str, expected_position: usize) {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(input);

        assert_eq!(
            parse_number(&mut cursor, &mut budget),
            Ok(expected.to_owned())
        );
        assert_eq!(cursor.position(), expected_position);
    }

    #[test]
    fn decimal_short_forms_render_exactly_and_consume_one_byte() {
        for (input, expected) in [(b"0x".as_slice(), "1"), (b"8x", "9"), (b"9x", "10")] {
            assert_number(input, expected, 1);
        }
    }

    #[test]
    fn optional_sign_is_consumed_and_rendered() {
        assert_number(b"?0x", "-1", 2);
        assert_number(b"?A@x", "-0", 3);
    }

    #[test]
    fn hexadecimal_form_uses_a_as_zero_and_consumes_terminator() {
        assert_number(b"A@x", "0", 2);
        assert_number(b"BA@x", "16", 3);
        assert_number(b"PP@x", "255", 3);
    }

    #[test]
    fn invalid_initial_byte_is_typed_and_unconsumed() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"Q");

        assert_eq!(
            parse_number(&mut cursor, &mut budget),
            Err(ParseFailure::InvalidNumberStart {
                offset: 0,
                found: Some(b'Q'),
            })
        );
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn lone_sign_remains_consumed_when_number_is_missing() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"?");

        assert_eq!(
            parse_number(&mut cursor, &mut budget),
            Err(ParseFailure::InvalidNumberStart {
                offset: 1,
                found: None,
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn missing_hexadecimal_terminator_at_eof_is_typed() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"BA");

        assert_eq!(
            parse_number(&mut cursor, &mut budget),
            Err(ParseFailure::MissingNumberTerminator {
                offset: 2,
                found: None,
            })
        );
        assert_eq!(cursor.position(), 2);
    }

    #[test]
    fn invalid_hexadecimal_terminator_stays_unconsumed() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"BA!");

        assert_eq!(
            parse_number(&mut cursor, &mut budget),
            Err(ParseFailure::MissingNumberTerminator {
                offset: 2,
                found: Some(b'!'),
            })
        );
        assert_eq!(cursor.position(), 2);
    }

    #[test]
    fn hexadecimal_accumulation_is_bounded_to_c_int_positive_range() {
        let mut budget = AttemptBudget::new();
        assert_number(b"HPPPPPPP@x", "2147483647", 9);

        let mut cursor = Cursor::new(b"IAAAAAAA@x");
        assert_eq!(
            parse_number(&mut cursor, &mut budget),
            Err(ParseFailure::NumberOverflow {
                start: 0,
                offset: 7,
                max: 2_147_483_647,
            })
        );
        // The C loop consumes each hexadecimal digit as it is accumulated. The safe
        // port therefore consumes the digit that proves overflow, but nothing after it.
        assert_eq!(cursor.position(), 8);
        assert_eq!(cursor.peek(0), Some(b'@'));
    }

    #[test]
    fn primitive_type_tables_match_the_c_switches_for_every_byte() {
        for byte in 0..=u8::MAX {
            let expected_ordinary = match byte {
                b'C' => Some("signed char"),
                b'D' => Some("char"),
                b'E' => Some("unsigned char"),
                b'F' => Some("short"),
                b'G' => Some("unsigned short"),
                b'H' => Some("int"),
                b'I' => Some("unsigned int"),
                b'J' => Some("long"),
                b'K' => Some("unsigned long"),
                b'M' => Some("float"),
                b'N' => Some("double"),
                b'O' => Some("long double"),
                b'X' => Some("void"),
                b'Z' => Some("..."),
                _ => None,
            };
            assert_eq!(
                ordinary_primitive_type(byte),
                expected_ordinary,
                "ordinary byte {byte:#04x}"
            );

            let expected_extended = match byte {
                b'D' => Some("__int8"),
                b'E' => Some("unsigned __int8"),
                b'F' => Some("__int16"),
                b'G' => Some("unsigned __int16"),
                b'H' => Some("__int32"),
                b'I' => Some("unsigned __int32"),
                b'J' => Some("__int64"),
                b'K' => Some("unsigned __int64"),
                b'L' => Some("__int128"),
                b'M' => Some("unsigned __int128"),
                b'N' => Some("bool"),
                b'W' => Some("wchar_t"),
                _ => None,
            };
            assert_eq!(
                extended_primitive_type(byte),
                expected_extended,
                "extended byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn calling_convention_complete_maps_a_through_m_exactly() {
        for (byte, calling_convention, exported) in [
            (b'A', Some("__cdecl"), None),
            (b'B', Some("__cdecl"), Some("__dll_export ")),
            (b'C', Some("__pascal"), None),
            (b'D', Some("__pascal"), Some("__dll_export ")),
            (b'E', Some("__thiscall"), None),
            (b'F', Some("__thiscall"), Some("__dll_export ")),
            (b'G', Some("__stdcall"), None),
            (b'H', Some("__stdcall"), Some("__dll_export ")),
            (b'I', Some("__fastcall"), None),
            (b'J', Some("__fastcall"), Some("__dll_export ")),
            (b'K', None, None),
            (b'L', None, Some("__dll_export ")),
            (b'M', Some("__clrcall"), None),
        ] {
            assert_eq!(
                decode_calling_convention(byte, UNDNAME_COMPLETE),
                Ok(CallingConvention {
                    calling_convention,
                    exported,
                }),
                "byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn calling_convention_no_leading_underscores_strips_exactly_two() {
        for (byte, calling_convention, exported) in [
            (b'A', Some("cdecl"), None),
            (b'B', Some("cdecl"), Some("dll_export ")),
            (b'C', Some("pascal"), None),
            (b'D', Some("pascal"), Some("dll_export ")),
            (b'E', Some("thiscall"), None),
            (b'F', Some("thiscall"), Some("dll_export ")),
            (b'G', Some("stdcall"), None),
            (b'H', Some("stdcall"), Some("dll_export ")),
            (b'I', Some("fastcall"), None),
            (b'J', Some("fastcall"), Some("dll_export ")),
            (b'K', None, None),
            (b'L', None, Some("dll_export ")),
            (b'M', Some("clrcall"), None),
        ] {
            assert_eq!(
                decode_calling_convention(byte, UNDNAME_NO_LEADING_UNDERSCORES),
                Ok(CallingConvention {
                    calling_convention,
                    exported,
                }),
                "byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn suppressed_calling_conventions_skip_validation_for_every_byte() {
        for flags in [
            UNDNAME_NO_MS_KEYWORDS,
            UNDNAME_NO_ALLOCATION_LANGUAGE,
            VMP_DEMANGLE_FLAGS,
        ] {
            for byte in 0..=u8::MAX {
                assert_eq!(
                    decode_calling_convention(byte, flags),
                    Ok(CallingConvention {
                        calling_convention: None,
                        exported: None,
                    }),
                    "flags {flags:#06x}, byte {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn active_invalid_calling_conventions_report_the_unsigned_byte() {
        for byte in [b'@', b'N', 0x80, u8::MAX] {
            assert_eq!(
                decode_calling_convention(byte, UNDNAME_COMPLETE),
                Err(ParseFailure::InvalidCallingConvention { found: byte })
            );
        }
    }

    #[test]
    fn active_calling_convention_oracle_covers_every_byte_independently() {
        for byte in 0..=u8::MAX {
            let expected = match byte {
                b'A' => Ok(CallingConvention {
                    calling_convention: Some("__cdecl"),
                    exported: None,
                }),
                b'B' => Ok(CallingConvention {
                    calling_convention: Some("__cdecl"),
                    exported: Some("__dll_export "),
                }),
                b'C' => Ok(CallingConvention {
                    calling_convention: Some("__pascal"),
                    exported: None,
                }),
                b'D' => Ok(CallingConvention {
                    calling_convention: Some("__pascal"),
                    exported: Some("__dll_export "),
                }),
                b'E' => Ok(CallingConvention {
                    calling_convention: Some("__thiscall"),
                    exported: None,
                }),
                b'F' => Ok(CallingConvention {
                    calling_convention: Some("__thiscall"),
                    exported: Some("__dll_export "),
                }),
                b'G' => Ok(CallingConvention {
                    calling_convention: Some("__stdcall"),
                    exported: None,
                }),
                b'H' => Ok(CallingConvention {
                    calling_convention: Some("__stdcall"),
                    exported: Some("__dll_export "),
                }),
                b'I' => Ok(CallingConvention {
                    calling_convention: Some("__fastcall"),
                    exported: None,
                }),
                b'J' => Ok(CallingConvention {
                    calling_convention: Some("__fastcall"),
                    exported: Some("__dll_export "),
                }),
                b'K' => Ok(CallingConvention {
                    calling_convention: None,
                    exported: None,
                }),
                b'L' => Ok(CallingConvention {
                    calling_convention: None,
                    exported: Some("__dll_export "),
                }),
                b'M' => Ok(CallingConvention {
                    calling_convention: Some("__clrcall"),
                    exported: None,
                }),
                found => Err(ParseFailure::InvalidCallingConvention { found }),
            };

            assert_eq!(
                decode_calling_convention(byte, UNDNAME_COMPLETE),
                expected,
                "byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn plain_class_name_preserves_exact_success_side_effects() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"Foo@@");
        let mut names = RefArray::with_limit(4);
        let mut stack = RefArray::with_limit(4);
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Ok("Foo".to_owned())
        );
        assert_eq!(cursor.position(), 5);
        assert_eq!(names.reference(0), Ok("Foo"));
        assert_eq!(stack.logical_num(), 0);
        assert_eq!(stack.reference(0), Ok("Foo"));
    }

    #[test]
    fn plain_class_name_renders_components_in_reverse() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"Inner@Outer@@");
        let mut names = RefArray::with_limit(4);
        let mut stack = RefArray::with_limit(4);
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Ok("Outer::Inner".to_owned())
        );
        assert_eq!(cursor.position(), 13);
        assert_eq!(stack.logical_num(), 0);
    }

    #[test]
    fn class_digit_uses_start_scoped_name_reference() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"0@");
        let mut names = RefArray::with_limit(4);
        names.push("Old", &mut budget).expect("within limit");
        names.push("Scoped", &mut budget).expect("within limit");
        names.set_start(1).expect("inside high water");
        let mut stack = RefArray::with_limit(2);
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Ok("Scoped".to_owned())
        );
        assert_eq!(cursor.position(), 2);
        assert_eq!(stack.logical_num(), 0);
    }

    #[test]
    fn missing_class_digit_reference_consumes_digit_and_restores_stack() {
        let mut budget = AttemptBudget::new();
        let mut cursor = Cursor::new(b"0@");
        let mut names = RefArray::with_limit(2);
        let mut stack = RefArray::with_limit(2);
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::ReferenceOutOfHighWater {
                start: 0,
                index: 0,
                max: 0
            })
        );
        assert_eq!(cursor.position(), 1);
        assert_eq!(stack.logical_num(), 0);
    }

    #[test]
    fn class_eof_keeps_literal_name_and_restores_stack() {
        let mut cursor = Cursor::new(b"Foo@");
        let mut names = RefArray::with_limit(2);
        let mut stack = RefArray::with_limit(2);
        let mut budget = AttemptBudget::new();
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::UnexpectedEnd { offset: 4 })
        );
        assert_eq!(cursor.position(), 4);
        assert_eq!(names.reference(0), Ok("Foo"));
        assert_eq!(stack.logical_num(), 0);
        assert_eq!(stack.reference(0), Ok("Foo"));
    }

    #[test]
    fn failed_class_attempts_do_not_refund_cumulative_budget() {
        let mut cursor = Cursor::new(b"Foo@?");
        let mut names = RefArray::with_limit(4);
        let mut stack = RefArray::with_limit(2);
        let mut budget = AttemptBudget::new();

        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::UnsupportedClassComponent {
                offset: 4,
                found: b'?',
            })
        );
        assert_eq!(budget.used(), 9);
        assert_eq!(stack.logical_num(), 0);

        let mut cursor = Cursor::new(b"Foo@?");
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::UnsupportedClassComponent {
                offset: 4,
                found: b'?',
            })
        );
        assert_eq!(budget.used(), 18, "rollback must not refund allocations");
        assert_eq!(stack.logical_num(), 0);
    }

    #[test]
    fn empty_class_consumes_terminator_and_is_rejected_safely() {
        let mut cursor = Cursor::new(b"@");
        let mut names = RefArray::with_limit(1);
        let mut stack = RefArray::with_limit(1);
        let mut budget = AttemptBudget::new();
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::EmptyClass { offset: 0 })
        );
        assert_eq!(cursor.position(), 1);
        assert_eq!(stack.logical_num(), 0);
    }

    #[test]
    fn unsupported_and_invalid_class_components_remain_unconsumed() {
        for (input, expected) in [
            (
                &b"?@"[..],
                ParseFailure::UnsupportedClassComponent {
                    offset: 0,
                    found: b'?',
                },
            ),
            (
                &[0x80, b'@'][..],
                ParseFailure::InvalidLiteral {
                    offset: 0,
                    found: Some(0x80),
                },
            ),
        ] {
            let mut cursor = Cursor::new(input);
            let mut names = RefArray::with_limit(1);
            let mut stack = RefArray::with_limit(1);
            let mut budget = AttemptBudget::new();
            assert_eq!(
                parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
                Err(expected)
            );
            assert_eq!(cursor.position(), 0);
            assert_eq!(stack.logical_num(), 0);
        }
    }

    #[test]
    fn stack_capacity_failure_keeps_name_and_consumption_but_rolls_back_stack() {
        let mut cursor = Cursor::new(b"Foo@@");
        let mut names = RefArray::with_limit(1);
        let mut stack = RefArray::with_limit(0);
        let mut budget = AttemptBudget::new();
        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0
            })
        );
        assert_eq!(cursor.position(), 4);
        assert_eq!(names.reference(0), Ok("Foo"));
        assert_eq!(stack.logical_num(), 0);
    }

    #[test]
    fn checked_class_output_len_accepts_exact_limit_and_rejects_one_over() {
        let current_len = MAX_OUTPUT_BYTES - 12;
        assert_eq!(
            checked_class_output_len(current_len, 10, true),
            Ok(MAX_OUTPUT_BYTES)
        );
        assert_eq!(
            checked_class_output_len(current_len, 11, true),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: MAX_OUTPUT_BYTES + 1,
                limit: MAX_OUTPUT_BYTES,
            })
        );
    }

    #[test]
    fn class_digit_output_limit_is_checked_before_clone_and_push() {
        let component_len = 64 * 1024;
        let component = "x".repeat(component_len);
        let component_count = MAX_OUTPUT_BYTES / component_len;
        let input = format!("{}@", "0".repeat(component_count));
        let expected_attempted = component_count * component_len + (component_count - 1) * 2;
        let mut cursor = Cursor::new(input.as_bytes());
        let mut names = RefArray::with_limit(1);
        let mut budget = AttemptBudget::new();
        names.push(&component, &mut budget).expect("within limit");
        let mut stack = RefArray::with_limit(component_count);

        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: expected_attempted,
                limit: MAX_OUTPUT_BYTES,
            })
        );
        assert_eq!(cursor.position(), component_count);
        assert_eq!(cursor.peek(0), Some(b'@'));
        assert_eq!(stack.logical_num(), 0);
        assert!(matches!(
            stack.reference(component_count - 1),
            Err(ParseFailure::ReferenceOutOfHighWater { max, .. }) if max == component_count - 1
        ));
        assert_eq!(names.reference(0), Ok(component.as_str()));
        assert!(matches!(
            names.reference(1),
            Err(ParseFailure::ReferenceOutOfHighWater { max: 1, .. })
        ));
    }

    #[test]
    fn cumulative_backreference_and_literal_copies_exhaust_one_attempt_budget() {
        let referenced_len = 64 * 1024;
        let referenced_component_count = MAX_OUTPUT_BYTES / referenced_len - 1;
        let current_len =
            referenced_component_count * referenced_len + (referenced_component_count - 1) * 2;
        let literal_len = MAX_OUTPUT_BYTES - current_len - 2 + 1;
        let literal = "y".repeat(literal_len);
        let input = format!("{}{}@@", "0".repeat(referenced_component_count), literal);
        let mut cursor = Cursor::new(input.as_bytes());
        let mut names = RefArray::with_limit(2);
        let mut budget = AttemptBudget::new();
        names
            .push(&"x".repeat(referenced_len), &mut budget)
            .expect("within limit");
        let mut stack = RefArray::with_limit(referenced_component_count + 1);

        assert_eq!(
            parse_plain_class_name(&mut cursor, &mut names, &mut stack, &mut budget),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: MAX_OUTPUT_BYTES + literal_len,
                limit: MAX_OUTPUT_BYTES,
            })
        );
        assert_eq!(
            cursor.position(),
            referenced_component_count + literal_len + 1
        );
        assert_eq!(cursor.peek(0), Some(b'@'));
        assert_eq!(stack.logical_num(), 0);
        assert!(matches!(
            stack.reference(referenced_component_count),
            Err(ParseFailure::ReferenceOutOfHighWater { max, .. })
                if max == referenced_component_count
        ));
        assert!(matches!(
            names.reference(1),
            Err(ParseFailure::ReferenceOutOfHighWater { max: 1, .. })
        ));
    }

    #[test]
    fn class_renderer_rejects_output_expansion_within_component_limit() {
        let mut stack = RefArray::with_limit(crate::limits::MAX_COMPONENTS);
        let component = "x".repeat(crate::limits::MAX_OUTPUT_BYTES / crate::limits::MAX_COMPONENTS);
        let mut budget = AttemptBudget::new();
        for _ in 0..crate::limits::MAX_COMPONENTS {
            stack
                .push(&component, &mut budget)
                .expect("within component limit");
        }
        assert!(matches!(
            render_class_name(&stack, 0, &mut budget),
            Err(ParseFailure::OutputLimitExceeded {
                limit: crate::limits::MAX_OUTPUT_BYTES,
                ..
            })
        ));
    }

    fn assert_top_level_method(input: &[u8], flags: u16, expected_full: &str, expected_name: &str) {
        let mut parser = MsvcParser::new(input, flags).expect("input within limit");
        let parsed = parser
            .parse_ordinary_method()
            .expect("supported ordinary method");
        assert_eq!(parsed.full_name(), expected_full);
        assert_eq!(parsed.name(), expected_name);
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.stack.logical_num(), 0);
    }

    fn assert_top_level_data(input: &[u8], flags: u16, expected: &str, cursor: usize) {
        let mut parser = MsvcParser::new(input, flags).expect("input within limit");
        let parsed = parser
            .parse_ordinary_data()
            .expect("supported ordinary data symbol");
        assert_eq!(parsed.full_name(), expected);
        assert_eq!(parsed.name(), expected);
        assert_eq!(parser.cursor.position(), cursor);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn ordinary_data_codes_zero_through_nine_render_and_consume_exactly() {
        for (input, expected, cursor) in [
            (b"?x@C@@0HA".as_slice(), "private: static int C::x", 9),
            (b"?x@C@@1HA", "protected: static int C::x", 9),
            (b"?x@C@@2HA", "public: static int C::x", 9),
            (b"?x@C@@3HA", "int C::x", 9),
            (b"?x@C@@4HA", "int C::x", 9),
            (b"?x@C@@5HA", "int C::x", 9),
            (b"?x@C@@6B@", "const C::x", 8),
            (b"?x@C@@7B@", "const C::x", 8),
            (b"?x@C@@8", "C::x", 7),
            (b"?x@C@@9", "C::x", 7),
        ] {
            assert_top_level_data(input, UNDNAME_COMPLETE, expected, cursor);
        }
        assert_top_level_data(b"?x@@3HA", UNDNAME_COMPLETE, "int x", 7);
        assert_top_level_data(
            b"?x@@3P6AHH@ZA",
            UNDNAME_COMPLETE,
            "int (__cdecl* x)(int)",
            13,
        );
    }

    #[test]
    fn ordinary_data_uses_a_fresh_local_parameter_type_table() {
        let mut parser = MsvcParser::new(b"?x@@30", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_ordinary_data(),
            Err(ParseFailure::ReferenceOutOfHighWater {
                start: 0,
                index: 0,
                max: 0,
            })
        );
        assert_eq!(parser.cursor.position(), 6);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn compiler_generated_data_preserves_native_at_and_for_class_quirks() {
        assert_top_level_data(b"?x@C@@6EB@", UNDNAME_COMPLETE, "const C::x", 9);
        assert_top_level_data(
            b"?x@C@@6BBase@@tail",
            UNDNAME_COMPLETE,
            "const C::x{for `Base'}",
            14,
        );
    }

    #[test]
    fn data_name_only_parses_before_suppressing_payload() {
        assert_top_level_data(
            b"?x@C@@0PAHA",
            crate::msvc::flags::UNDNAME_NAME_ONLY,
            "C::x",
            11,
        );

        let mut malformed = MsvcParser::new(b"?x@C@@0!", crate::msvc::flags::UNDNAME_NAME_ONLY)
            .expect("within limit");
        assert_eq!(
            malformed.parse_ordinary_data(),
            Err(ParseFailure::InvalidDatatypeCode {
                offset: 7,
                found: b'!',
            })
        );
        assert_eq!(malformed.stack.logical_num(), 0);
    }

    #[test]
    fn data_flags_and_modifier_combinations_match_native_render_order() {
        for (input, complete, vmp, name_only) in [
            (
                b"?x@C@@0HEB".as_slice(),
                "private: static int const __ptr64 C::x",
                "int const C::x",
                "C::x",
            ),
            (b"?x@C@@3HEA", "int __ptr64 C::x", "int C::x", "C::x"),
            (b"?x@C@@5HB", "int const C::x", "int const C::x", "C::x"),
        ] {
            assert_top_level_data(input, UNDNAME_COMPLETE, complete, input.len());
            assert_top_level_data(input, VMP_DEMANGLE_FLAGS, vmp, input.len());
            assert_top_level_data(
                input,
                crate::msvc::flags::UNDNAME_NAME_ONLY,
                name_only,
                input.len(),
            );
        }
    }

    #[test]
    fn data_failures_restore_stack_but_preserve_cursor_names_and_budget() {
        let input = b"?x@@3VFoo@@!";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_ordinary_data(),
            Err(ParseFailure::InvalidModifier {
                offset: 11,
                found: b'!',
            })
        );
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(parser.names.reference(0), Ok("x"));
        assert_eq!(parser.names.reference(1), Ok("Foo"));
        assert!(parser.budget.used() > 0);

        let mut invalid = MsvcParser::new(b"?x@@!tail", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            invalid.parse_ordinary_data(),
            Err(ParseFailure::UnsupportedMethodEncoding {
                offset: 4,
                found: b'!',
            })
        );
        assert_eq!(invalid.cursor.position(), 4);
        assert_eq!(invalid.stack.logical_num(), 0);
    }

    #[test]
    fn data_final_allocation_honors_exact_cumulative_budget_boundary() {
        let input = b"?x@C@@0HA";
        let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        measured
            .parse_ordinary_data()
            .expect("measure successful data parse");
        let exact = measured.budget.used();
        assert!(exact > 0);

        let mut accepted = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        accepted.budget = AttemptBudget::with_limit(exact);
        assert!(accepted.parse_ordinary_data().is_ok());

        let mut rejected = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        rejected.budget = AttemptBudget::with_limit(exact - 1);
        assert!(matches!(
            rejected.parse_ordinary_data(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(rejected.stack.logical_num(), 0);
    }

    #[test]
    fn top_level_method_matches_four_reference_golden_selectors_and_c_oracle_offsets() {
        for (input, full, name, name_pos) in [
            (
                b"?newCol@QColorPicker@?A0x3be3cb80@@QEAAXHH@Z".as_slice(),
                "void `anonymous namespace'::QColorPicker::newCol(int,int)",
                "`anonymous namespace'::QColorPicker::newCol(int,int)",
                5,
            ),
            (
                b"?InitWorkspacesCollection@CDaoWorkspace@@IAEXXZ",
                "void CDaoWorkspace::InitWorkspacesCollection(void)",
                "CDaoWorkspace::InitWorkspacesCollection(void)",
                5,
            ),
            (
                b"?Invoke@XEventSink@COleControlSite@@UAGJJABU_GUID@@KGPAUtagDISPPARAMS@@PAUtagVARIANT@@PAUtagEXCEPINFO@@PAI@Z",
                "long COleControlSite::XEventSink::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)",
                "COleControlSite::XEventSink::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)",
                5,
            ),
            (
                b"?IsNullValue@CDaoFieldExchange@@SGHPAXK@Z",
                "int CDaoFieldExchange::IsNullValue(void *,unsigned long)",
                "CDaoFieldExchange::IsNullValue(void *,unsigned long)",
                4,
            ),
        ] {
            let mut parser =
                MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("input within limit");
            let parsed = parser
                .parse_ordinary_method()
                .expect("supported ordinary method");
            assert_eq!(parsed.full_name(), full);
            assert_eq!(parsed.name(), name);
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn parser_paths_match_all_five_reference_golden_selectors() {
        let ordinary = [
            (
                b"?newCol@QColorPicker@?A0x3be3cb80@@QEAAXHH@Z".as_slice(),
                "void `anonymous namespace'::QColorPicker::newCol(int,int)",
                "`anonymous namespace'::QColorPicker::newCol(int,int)",
            ),
            (
                b"?InitWorkspacesCollection@CDaoWorkspace@@IAEXXZ".as_slice(),
                "void CDaoWorkspace::InitWorkspacesCollection(void)",
                "CDaoWorkspace::InitWorkspacesCollection(void)",
            ),
            (
                b"?Invoke@XEventSink@COleControlSite@@UAGJJABU_GUID@@KGPAUtagDISPPARAMS@@PAUtagVARIANT@@PAUtagEXCEPINFO@@PAI@Z".as_slice(),
                "long COleControlSite::XEventSink::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)",
                "COleControlSite::XEventSink::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)",
            ),
            (
                b"?IsNullValue@CDaoFieldExchange@@SGHPAXK@Z".as_slice(),
                "int CDaoFieldExchange::IsNullValue(void *,unsigned long)",
                "CDaoFieldExchange::IsNullValue(void *,unsigned long)",
            ),
        ];
        for (input, full, name) in ordinary {
            let mut parser =
                MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("input within limit");
            let parsed = parser
                .parse_ordinary_method()
                .expect("ordinary golden selector");
            assert_eq!(parsed.full_name(), full);
            assert_eq!(parsed.name(), name);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let input = b"??$?0VQObject@@@?$QWeakPointer@VQObject@@@@AEAA@PEAVQObject@@_N@Z";
        let mut parser = MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("input within limit");
        let parsed = parser
            .parse_operator_method()
            .expect("template constructor golden selector");
        let expected =
            "QWeakPointer<class QObject>::<class QObject>::<class QObject>(class QObject *,bool)";
        assert_eq!(parsed.full_name(), expected);
        assert_eq!(parsed.name(), expected);
        assert_eq!(parsed.full_name().len() - parsed.name().len(), 0);
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn constructor_and_destructor_match_c_oracle_for_complete_vmp_and_name_only() {
        for (input, complete, vmp, name_only) in [
            (
                b"??0C@@QAE@XZ".as_slice(),
                "public: __thiscall C::C(void)",
                "C::C(void)",
                "C::C",
            ),
            (
                b"??1C@@QAE@XZ".as_slice(),
                "public: __thiscall C::~C(void)",
                "C::~C(void)",
                "C::~C",
            ),
        ] {
            for (flags, expected, name_pos) in [
                (UNDNAME_COMPLETE, complete, 19),
                (VMP_DEMANGLE_FLAGS, vmp, 0),
                (crate::msvc::flags::UNDNAME_NAME_ONLY, name_only, 0),
            ] {
                let mut parser = MsvcParser::new(input, flags).expect("input within limit");
                let parsed = parser
                    .parse_operator_method()
                    .expect("supported constructor/destructor");
                assert_eq!(parsed.full_name(), expected);
                assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
                assert_eq!(parser.cursor.position(), input.len());
                assert_eq!(parser.stack.logical_num(), 0);
            }
        }
    }

    #[test]
    fn simple_operators_match_bundled_c_oracle() {
        for (input, complete, complete_name, vmp, vmp_name, name_only) in [
            (
                b"??2@YAPAXI@Z".as_slice(),
                "void * __cdecl operator new(unsigned int)",
                "operator new(unsigned int)",
                "void * operator new(unsigned int)",
                "operator new(unsigned int)",
                "operator new",
            ),
            (
                b"??3@YAXPAX@Z",
                "void __cdecl operator delete(void *)",
                "operator delete(void *)",
                "void operator delete(void *)",
                "operator delete(void *)",
                "operator delete",
            ),
            (
                b"??HC@@QAEHH@Z",
                "public: int __thiscall C::operator+(int)",
                "C::operator+(int)",
                "int C::operator+(int)",
                "C::operator+(int)",
                "C::operator+",
            ),
            (
                b"??AC@@QAEHH@Z",
                "public: int __thiscall C::operator[](int)",
                "C::operator[](int)",
                "int C::operator[](int)",
                "C::operator[](int)",
                "C::operator[]",
            ),
            (
                b"??_U@YAPAXI@Z",
                "void * __cdecl operator new[](unsigned int)",
                "operator new[](unsigned int)",
                "void * operator new[](unsigned int)",
                "operator new[](unsigned int)",
                "operator new[]",
            ),
            (
                b"??_EC@@UAEPAXI@Z",
                "public: virtual void * __thiscall C::`vector deleting destructor'(unsigned int)",
                "C::`vector deleting destructor'(unsigned int)",
                "void * C::`vector deleting destructor'(unsigned int)",
                "C::`vector deleting destructor'(unsigned int)",
                "C::`vector deleting destructor'",
            ),
        ] {
            for (flags, expected, expected_name) in [
                (UNDNAME_COMPLETE, complete, complete_name),
                (VMP_DEMANGLE_FLAGS, vmp, vmp_name),
                (crate::msvc::flags::UNDNAME_NAME_ONLY, name_only, name_only),
            ] {
                let mut parser = MsvcParser::new(input, flags).expect("input within limit");
                let parsed = parser
                    .parse_operator_method()
                    .expect("supported simple operator");
                assert_eq!(parsed.full_name(), expected);
                assert_eq!(parsed.name(), expected_name);
                assert_eq!(parser.cursor.position(), input.len());
                assert_eq!(parser.stack.logical_num(), 0);
            }
        }
    }

    #[test]
    fn every_supported_simple_operator_has_exact_static_spelling_and_consumes_its_code() {
        let cases = [
            ("2", "operator new"),
            ("3", "operator delete"),
            ("4", "operator="),
            ("5", "operator>>"),
            ("6", "operator<<"),
            ("7", "operator!"),
            ("8", "operator=="),
            ("9", "operator!="),
            ("A", "operator[]"),
            ("C", "operator->"),
            ("D", "operator*"),
            ("E", "operator++"),
            ("F", "operator--"),
            ("G", "operator-"),
            ("H", "operator+"),
            ("I", "operator&"),
            ("J", "operator->*"),
            ("K", "operator/"),
            ("L", "operator%"),
            ("M", "operator<"),
            ("N", "operator<="),
            ("O", "operator>"),
            ("P", "operator>="),
            ("Q", "operator,"),
            ("R", "operator()"),
            ("S", "operator~"),
            ("T", "operator^"),
            ("U", "operator|"),
            ("V", "operator&&"),
            ("W", "operator||"),
            ("X", "operator*="),
            ("Y", "operator+="),
            ("Z", "operator-="),
            ("_0", "operator/="),
            ("_1", "operator%="),
            ("_2", "operator>>="),
            ("_3", "operator<<="),
            ("_4", "operator&="),
            ("_5", "operator|="),
            ("_6", "operator^="),
            ("_7", "`vftable'"),
            ("_8", "`vbtable'"),
            ("_9", "`vcall'"),
            ("_A", "`typeof'"),
            ("_B", "`local static guard'"),
            ("_D", "`vbase destructor'"),
            ("_E", "`vector deleting destructor'"),
            ("_F", "`default constructor closure'"),
            ("_G", "`scalar deleting destructor'"),
            ("_H", "`vector constructor iterator'"),
            ("_I", "`vector destructor iterator'"),
            ("_J", "`vector vbase constructor iterator'"),
            ("_K", "`virtual displacement map'"),
            ("_L", "`eh vector constructor iterator'"),
            ("_M", "`eh vector destructor iterator'"),
            ("_N", "`eh vector vbase constructor iterator'"),
            ("_O", "`copy constructor closure'"),
            ("_S", "`local vftable'"),
            ("_T", "`local vftable constructor closure'"),
            ("_U", "operator new[]"),
            ("_V", "operator delete[]"),
            ("_X", "`placement delete closure'"),
            ("_Y", "`placement delete[] closure'"),
            ("__A", "`managed vector constructor iterator'"),
            ("__B", "`managed vector destructor iterator'"),
            ("__C", "`eh vector copy constructor iterator'"),
            ("__D", "`eh vector vbase copy constructor iterator'"),
            ("__G", "`vector copy constructor iterator'"),
        ];
        for (code, spelling) in cases {
            let mut input = Vec::new();
            input.extend_from_slice(b"??");
            input.extend_from_slice(code.as_bytes());
            input.extend_from_slice(b"@YAXXZ");
            let mut parser = MsvcParser::new(&input, UNDNAME_COMPLETE).expect("within limit");
            let parsed = parser
                .parse_operator_method()
                .expect("supported table entry");
            let mut expected = String::from("void __cdecl ");
            expected.push_str(spelling);
            expected.push_str("(void)");
            assert_eq!(parsed.full_name(), expected, "operator code {code}");
            assert_eq!(
                parser.cursor.position(),
                input.len(),
                "operator code {code}"
            );
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn conversion_operator_always_expands_target_type_into_selector_name() {
        for (input, complete, complete_name, vmp, name_only) in [
            (
                b"??BC@@QAEHXZ".as_slice(),
                "public: __thiscall C::operator int(void)",
                "C::operator int(void)",
                "C::operator int(void)",
                "C::operator int",
            ),
            (
                b"??BC@@QAEPAHXZ",
                "public: __thiscall C::operator int *(void)",
                "C::operator int *(void)",
                "C::operator int *(void)",
                "C::operator int *",
            ),
            (
                b"??BC@@QAEP6AHH@ZXZ",
                "public: __thiscall C::operator int (__cdecl*)(int)(void)",
                "C::operator int (__cdecl*)(int)(void)",
                "C::operator int (*)(int)(void)",
                "C::operator int (__cdecl*)(int)",
            ),
        ] {
            for (flags, expected, expected_name) in [
                (UNDNAME_COMPLETE, complete, complete_name),
                (VMP_DEMANGLE_FLAGS, vmp, vmp),
                (crate::msvc::flags::UNDNAME_NAME_ONLY, name_only, name_only),
            ] {
                let mut parser = MsvcParser::new(input, flags).expect("within limit");
                let parsed = parser.parse_operator_method().expect("conversion operator");
                assert_eq!(parsed.full_name(), expected);
                assert_eq!(parsed.name(), expected_name);
                assert_eq!(parser.cursor.position(), input.len());
                assert_eq!(parser.stack.logical_num(), 0);
            }
        }
    }

    #[test]
    fn template_operator_uses_local_backrefs_supports_dtor_and_swallows_argument_failure() {
        let mut local_backref = MsvcParser::new(b"??$?0PAH0@C@@QAE@XZ", VMP_DEMANGLE_FLAGS)
            .expect("input within limit");
        let parsed = local_backref
            .parse_operator_method()
            .expect("template argument PMT is local and shared");
        assert_eq!(parsed.full_name(), "C::<int *,int *>::<int *,int *>(void)");
        assert_eq!(local_backref.stack.logical_num(), 0);
        assert_eq!(local_backref.names.logical_start(), 0);

        let input = b"??$?1VQObject@@@?$QWeakPointer@VQObject@@@@AEAA@PEAVQObject@@_N@Z";
        let mut destructor =
            MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("input within limit");
        let parsed = destructor
            .parse_operator_method()
            .expect("template destructor");
        assert_eq!(
            parsed.full_name(),
            "QWeakPointer<class QObject>::<class QObject>::~<class QObject>(class QObject *,bool)"
        );
        assert_eq!(destructor.cursor.position(), input.len());
        assert_eq!(destructor.stack.logical_num(), 0);

        let mut swallowed =
            MsvcParser::new(b"??$?0$XC@@QAE@XZ", VMP_DEMANGLE_FLAGS).expect("input within limit");
        let parsed = swallowed
            .parse_operator_method()
            .expect("native malformed-template-argument fallback");
        assert_eq!(parsed.full_name(), "C::C(void)");
        assert_eq!(swallowed.cursor.position(), 16);
        assert_eq!(swallowed.stack.logical_num(), 0);
        assert_eq!(swallowed.names.logical_start(), 0);

        let mut simple =
            MsvcParser::new(b"??$?HH@C@@QAEHH@Z", UNDNAME_COMPLETE).expect("input within limit");
        let parsed = simple
            .parse_operator_method()
            .expect("simple template operator");
        assert_eq!(
            parsed.full_name(),
            "public: int __thiscall C::operator+<int>(int)"
        );
        assert_eq!(simple.cursor.position(), 17);
        assert_eq!(simple.stack.logical_num(), 0);

        let malformed_input = b"??$?H$XC@@QAEHH@Z";
        let mut malformed =
            MsvcParser::new(malformed_input, UNDNAME_COMPLETE).expect("input within limit");
        let parsed = malformed
            .parse_operator_method()
            .expect("malformed template arguments retain the static base");
        assert_eq!(
            parsed.full_name(),
            "public: int __thiscall C::operator+(int)"
        );
        assert_eq!(malformed.cursor.position(), malformed_input.len());
        assert_eq!(malformed.stack.logical_num(), 0);
    }

    #[test]
    fn operator_front_reports_exact_prefix_code_and_class_failures_and_restores_stack() {
        for (input, expected, position) in [
            (
                b"plain".as_slice(),
                ParseFailure::InvalidMsvcPrefix {
                    offset: 0,
                    found: Some(b'p'),
                },
                0,
            ),
            (
                b"?x",
                ParseFailure::InvalidOperatorPrefix {
                    offset: 1,
                    found: Some(b'x'),
                },
                1,
            ),
            (
                b"??$0",
                ParseFailure::InvalidOperatorPrefix {
                    offset: 1,
                    found: Some(b'?'),
                },
                1,
            ),
            (
                b"??!",
                ParseFailure::UnsupportedOperatorCode {
                    offset: 2,
                    found: b'!',
                },
                3,
            ),
            (
                b"??$?!",
                ParseFailure::UnsupportedOperatorCode {
                    offset: 4,
                    found: b'!',
                },
                5,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_operator_method(), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        for (input, offset, position) in [(b"??".as_slice(), 2, 2), (b"??$?", 4, 4)] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(
                parser.parse_operator_method(),
                Err(ParseFailure::UnexpectedEnd { offset })
            );
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let mut missing_class =
            MsvcParser::new(b"??0@QAE@XZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            missing_class.parse_operator_method(),
            Err(ParseFailure::EmptyClass { offset: 4 })
        );
        assert_eq!(missing_class.stack.logical_num(), 0);
    }

    #[test]
    fn rtti_real_corpus_rows_render_exact_full_selector_and_cursor() {
        for (input, expected) in [
            (
                b"??_R0?AV__non_rtti_object@std@@@8".as_slice(),
                "class std::__non_rtti_object `RTTI Type Descriptor'",
            ),
            (
                b"??_R0?AVtype_info@@@8",
                "class type_info `RTTI Type Descriptor'",
            ),
            (
                b"??_R1A@?0A@EA@__non_rtti_object@std@@8",
                "std::__non_rtti_object::`RTTI Base Class Descriptor at (0,-1,0,64)'",
            ),
            (
                b"??_R1A@?0A@EA@type_info@@8",
                "type_info::`RTTI Base Class Descriptor at (0,-1,0,64)'",
            ),
            (
                b"??_R2bad_alloc@std@@8",
                "std::bad_alloc::`RTTI Base Class Array'",
            ),
            (
                b"??_R3logic_error@std@@8",
                "std::logic_error::`RTTI Class Hierarchy Descriptor'",
            ),
            (
                b"??_R4type_info@@6B@",
                "const type_info::`RTTI Complete Object Locator'",
            ),
        ] {
            let mut parser = MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("within limit");
            let parsed = parser.parse_operator_method().expect("real RTTI fixture");
            assert_eq!(parsed.full_name(), expected);
            assert_eq!(parsed.name(), expected);
            let expected_position = if input == b"??_R4type_info@@6B@" {
                18
            } else {
                input.len()
            };
            assert_eq!(parser.cursor.position(), expected_position);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn rtti_type_descriptor_folds_recursive_left_right_and_parses_under_name_only() {
        for (input, flags, expected) in [
            (
                b"??_R0P6AHXZ@8".as_slice(),
                UNDNAME_COMPLETE,
                "int (__cdecl*)(void) `RTTI Type Descriptor'",
            ),
            (
                b"??_R0?AVtype_info@@@8",
                UNDNAME_NAME_ONLY,
                "type_info `RTTI Type Descriptor'",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("within limit");
            let parsed = parser
                .parse_operator_method()
                .expect("RTTI type descriptor");
            assert_eq!(parsed.full_name(), expected);
            assert_eq!(parsed.name(), expected);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
            assert_eq!(parser.depth, 0);
        }

        let mut malformed =
            MsvcParser::new(b"??_R0!tail", UNDNAME_NAME_ONLY).expect("within limit");
        assert_eq!(
            malformed.parse_operator_method(),
            Err(ParseFailure::InvalidDatatypeCode {
                offset: 5,
                found: b'!'
            })
        );
        assert_eq!(malformed.cursor.position(), 6);
        assert_eq!(malformed.stack.logical_num(), 0);
        assert_eq!(malformed.depth, 0);
        assert_eq!(malformed.budget.used(), 0);

        let mut retained =
            MsvcParser::new(b"??_R0?AVtype_info@@@8", UNDNAME_COMPLETE).expect("within limit");
        retained
            .parse_operator_method()
            .expect("RTTI type descriptor");
        assert_eq!(retained.names.reference(0), Ok("type_info"));
        assert_eq!(
            retained.stack.reference(0),
            Ok("class type_info `RTTI Type Descriptor'")
        );
        assert_eq!(retained.stack.logical_num(), 0);
    }

    #[test]
    fn rtti_base_descriptor_uses_all_number_forms_and_preserves_partial_failures() {
        let input = b"??_R1?09BA@A@C@@8";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        let parsed = parser
            .parse_operator_method()
            .expect("four encoded numbers");
        assert_eq!(
            parsed.full_name(),
            "C::`RTTI Base Class Descriptor at (-1,10,16,0)'"
        );
        assert_eq!(parsed.name(), parsed.full_name());
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.stack.logical_num(), 0);

        for (input, expected, position, used) in [
            (
                b"??_R1".as_slice(),
                ParseFailure::InvalidNumberStart {
                    offset: 5,
                    found: None,
                },
                5,
                0,
            ),
            (
                b"??_R1A",
                ParseFailure::MissingNumberTerminator {
                    offset: 6,
                    found: None,
                },
                6,
                0,
            ),
            (
                b"??_R1A@",
                ParseFailure::InvalidNumberStart {
                    offset: 7,
                    found: None,
                },
                7,
                1,
            ),
            (
                b"??_R1A@?0",
                ParseFailure::InvalidNumberStart {
                    offset: 9,
                    found: None,
                },
                9,
                3,
            ),
            (
                b"??_R1A@?00",
                ParseFailure::InvalidNumberStart {
                    offset: 10,
                    found: None,
                },
                10,
                4,
            ),
            (
                b"??_R1PPPPPPPP@",
                ParseFailure::NumberOverflow {
                    start: 5,
                    offset: 12,
                    max: MAX_ENCODED_NUMBER,
                },
                13,
                0,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(parser.parse_operator_method(), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.budget.used(), used);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        for (input, start, offset, position, used) in [
            (b"??_R10PPPPPPPP@".as_slice(), 6, 13, 14, 1),
            (b"??_R100PPPPPPPP@", 7, 14, 15, 2),
            (b"??_R1000PPPPPPPP@", 8, 15, 16, 3),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(
                parser.parse_operator_method(),
                Err(ParseFailure::NumberOverflow {
                    start,
                    offset,
                    max: MAX_ENCODED_NUMBER,
                })
            );
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.budget.used(), used);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn rtti_names_are_charged_cumulatively_and_template_and_method_tails_stay_generic() {
        let input = b"??_R1A@?0A@EA@C@@8";
        let mut baseline = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        baseline
            .parse_operator_method()
            .expect("baseline RTTI parse");
        let exact_cost = baseline.budget.used();

        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        exact.budget = AttemptBudget::with_limit(exact_cost);
        assert!(exact.parse_operator_method().is_ok());
        assert_eq!(exact.budget.used(), exact_cost);
        assert_eq!(exact.stack.logical_num(), 0);

        let mut one_over = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        one_over.budget = AttemptBudget::with_limit(exact_cost - 1);
        assert!(matches!(
            one_over.parse_operator_method(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert!(one_over.budget.used() < exact_cost);
        assert_eq!(one_over.stack.logical_num(), 0);

        for (input, expected) in [
            (
                b"??$?_R2H@C@@8".as_slice(),
                "C::`RTTI Base Class Array'<int>",
            ),
            (b"??_R2@YAPAHXZ", "__cdecl `RTTI Base Class Array'(void)"),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            let parsed = parser.parse_operator_method().expect("generic RTTI tail");
            assert_eq!(parsed.full_name(), expected);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn immediate_string_operator_matches_real_corpus_and_ignores_every_tail() {
        let cases = [
            b"??_C@_00CNPNBAHC@?$AA@".as_slice(),
            b"??_C@_01CLKCMJKC@?5?$AA@",
            b"??_C@_01DCLJPIOD@?$CB?$AA@",
            b"??_C@_01DNKMNLPK@?$HM?$AA@",
            b"??_C@_01EEMJAFIK@?6?$AA@",
            b"??_Cordinary-looking-class@@6B@",
            b"??_C!not-a-signature",
            b"??_C\x80\xff@",
            b"??_C",
        ];
        for flags in [UNDNAME_COMPLETE, VMP_DEMANGLE_FLAGS, UNDNAME_NAME_ONLY] {
            for input in cases {
                let mut parser = MsvcParser::new(input, flags).expect("within limit");
                let parsed = parser
                    .parse_operator_method()
                    .expect("immediate string operator");
                assert_eq!(parsed.full_name(), "`string'");
                assert_eq!(parsed.name(), "`string'");
                assert_eq!(parsed.full_name().len() - parsed.name().len(), 0);
                assert_eq!(parser.cursor.position(), 4);
                assert_eq!(parser.stack.logical_num(), 0);
                assert_eq!(parser.names.logical_num(), 0);
            }
        }
    }

    #[test]
    fn immediate_string_operator_matches_every_real_corpus_row_under_all_relevant_flags() {
        let mut matched = 0usize;
        for line in include_str!("../../tests/fixtures/msvc_corpus.tsv").lines() {
            let Some(raw_field) = line.split('\t').next() else {
                continue;
            };
            let Some(raw) = raw_field
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            else {
                continue;
            };
            if !raw.starts_with("??_C") {
                continue;
            }
            matched += 1;
            for flags in [UNDNAME_COMPLETE, VMP_DEMANGLE_FLAGS, UNDNAME_NAME_ONLY] {
                let mut parser =
                    MsvcParser::new(raw.as_bytes(), flags).expect("fixture input within limit");
                let parsed = parser
                    .parse_operator_method()
                    .expect("fixture string operator");
                assert_eq!(parsed.full_name(), "`string'", "raw={raw}");
                assert_eq!(parsed.name(), "`string'", "raw={raw}");
                assert_eq!(parser.cursor.position(), 4, "raw={raw}");
                assert_eq!(parser.stack.logical_num(), 0, "raw={raw}");
            }
        }
        assert_eq!(matched, 916);
    }

    #[test]
    fn public_msvc_demangler_matches_every_map_fixture_row() {
        let mut total = 0usize;
        let mut exact = 0usize;
        let mut rejected = 0usize;
        let mut full_mismatch = 0usize;
        let mut selector_mismatch = 0usize;
        let mut examples = Vec::new();
        examples.try_reserve_exact(20).expect("bounded diagnostics");

        for line in include_str!("../../tests/fixtures/msvc_corpus.tsv").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "fixture row must have four fields");
            let raw = decode_tsv_string(fields[0]).expect("valid raw fixture string");
            let expected_full = decode_tsv_string(fields[1]).expect("valid full fixture string");
            let expected_pos = fields[2].parse::<usize>().expect("valid fixture offset");
            let expected_selector =
                decode_tsv_string(fields[3]).expect("valid selector fixture string");
            assert_eq!(
                expected_full.get(expected_pos..),
                Some(expected_selector.as_str())
            );

            total += 1;
            let actual = crate::demangle_name(&raw);
            let full_matches = actual.full_name() == expected_full;
            let selector_matches = actual.name() == expected_selector;
            if full_matches && selector_matches {
                exact += 1;
                continue;
            }
            if actual.full_name() == raw {
                rejected += 1;
            } else if !full_matches {
                full_mismatch += 1;
            } else {
                selector_mismatch += 1;
            }
            if examples.len() < 20 {
                examples.push(format!(
                    "raw={raw:?} expected=({expected_full:?}, {expected_selector:?}) actual=({:?}, {:?})",
                    actual.full_name(),
                    actual.name()
                ));
            }
        }

        assert_eq!(total, 1_539);
        assert_eq!(
            exact,
            total,
            "MSVC corpus exact={exact}/{total}, rejected={rejected}, full_mismatch={full_mismatch}, selector_mismatch={selector_mismatch}; examples={examples:#?}"
        );
    }

    #[test]
    fn immediate_string_operator_charges_one_owned_output_cumulatively() {
        let input = b"??_Cignored";
        let output = "`string'";

        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        exact.budget = AttemptBudget::with_limit(output.len());
        let parsed = exact
            .parse_operator_method()
            .expect("exact output budget succeeds");
        assert_eq!(parsed.full_name(), output);
        assert_eq!(exact.budget.used(), output.len());
        assert_eq!(exact.cursor.position(), 4);
        assert_eq!(exact.stack.logical_num(), 0);

        let mut one_over = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        one_over.budget = AttemptBudget::with_limit(output.len() - 1);
        assert!(matches!(
            one_over.parse_operator_method(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(one_over.budget.used(), 0);
        assert_eq!(one_over.cursor.position(), 4);
        assert_eq!(one_over.stack.logical_num(), 0);

        let prior = 3;
        let mut cumulative = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        cumulative.budget = AttemptBudget::with_used_and_limit(prior, prior + output.len());
        assert!(cumulative.parse_operator_method().is_ok());
        assert_eq!(cumulative.budget.used(), prior + output.len());
        assert_eq!(cumulative.stack.logical_num(), 0);
    }

    #[test]
    fn immediate_string_template_arguments_run_before_return_with_native_fallback() {
        let mut valid =
            MsvcParser::new(b"??$?_CVFoo@@@ignored", UNDNAME_COMPLETE).expect("within limit");
        let parsed = valid
            .parse_operator_method()
            .expect("valid template arguments append to string name");
        assert_eq!(parsed.full_name(), "`string'<class Foo>");
        assert_eq!(parsed.name(), parsed.full_name());
        assert_eq!(valid.cursor.position(), 13);
        assert_eq!(valid.stack.logical_num(), 0);
        assert_eq!(valid.names.logical_num(), 0);
        assert_eq!(valid.names.reference(0), Ok("Foo"));

        let mut malformed =
            MsvcParser::new(b"??$?_C$Xignored", UNDNAME_COMPLETE).expect("within limit");
        let parsed = malformed
            .parse_operator_method()
            .expect("malformed template arguments retain static base");
        assert_eq!(parsed.full_name(), "`string'");
        assert_eq!(parsed.name(), parsed.full_name());
        assert_eq!(malformed.cursor.position(), 8);
        assert_eq!(malformed.stack.logical_num(), 0);
        assert_eq!(malformed.names.logical_num(), 0);

        let primitive_input = b"??$?_CH@ignored";
        let primitive_output = "`string'<int>";
        let primitive_cost = "int".len() * 2 + "<int>".len() + primitive_output.len();
        let mut exact = MsvcParser::new(primitive_input, UNDNAME_COMPLETE).expect("within limit");
        exact.budget = AttemptBudget::with_limit(primitive_cost);
        let parsed = exact
            .parse_operator_method()
            .expect("template result is moved without another owned copy");
        assert_eq!(parsed.full_name(), primitive_output);
        assert_eq!(exact.budget.used(), primitive_cost);
        assert_eq!(exact.cursor.position(), 8);
        assert_eq!(exact.stack.logical_num(), 0);

        let mut one_over =
            MsvcParser::new(primitive_input, UNDNAME_COMPLETE).expect("within limit");
        one_over.budget = AttemptBudget::with_limit(primitive_cost - 1);
        assert!(matches!(
            one_over.parse_operator_method(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(one_over.cursor.position(), 8);
        assert_eq!(one_over.stack.logical_num(), 0);
    }

    #[test]
    fn dynamic_initializer_and_destructor_match_native_oracle_views() {
        for (input, complete, project, name_only) in [
            (
                b"??__E?x@@3HA@@YAXXZ".as_slice(),
                "void __cdecl `dynamic initializer for 'int x''(void)",
                "void `dynamic initializer for 'int x''(void)",
                "`dynamic initializer for 'x''",
            ),
            (
                b"??__F?x@@3HA@@YAXXZ",
                "void __cdecl `dynamic atexit destructor for 'int x''(void)",
                "void `dynamic atexit destructor for 'int x''(void)",
                "`dynamic atexit destructor for 'x''",
            ),
            (
                b"??__Ex@@YAXXZ",
                "void __cdecl `dynamic initializer for 'x''(void)",
                "void `dynamic initializer for 'x''(void)",
                "`dynamic initializer for 'x''",
            ),
            (
                b"??__Fx@@YAXXZ",
                "void __cdecl `dynamic atexit destructor for 'x''(void)",
                "void `dynamic atexit destructor for 'x''(void)",
                "`dynamic atexit destructor for 'x''",
            ),
            (
                b"??__E?f@@YAHXZ@@YAXXZ",
                "void __cdecl `dynamic initializer for 'int __cdecl f(void)''(void)",
                "void `dynamic initializer for 'int f(void)''(void)",
                "`dynamic initializer for 'f''",
            ),
            (
                b"??__F?f@@YAHXZ@@YAXXZ",
                "void __cdecl `dynamic atexit destructor for 'int __cdecl f(void)''(void)",
                "void `dynamic atexit destructor for 'int f(void)''(void)",
                "`dynamic atexit destructor for 'f''",
            ),
        ] {
            for (flags, expected, name_offset) in [
                (UNDNAME_COMPLETE, complete, 13),
                (VMP_DEMANGLE_FLAGS, project, 5),
                (UNDNAME_NAME_ONLY, name_only, 0),
            ] {
                let mut parser = MsvcParser::new(input, flags).expect("input within limit");
                let parsed = parser.parse_symbol().expect("dynamic operator parses");
                assert_eq!(parsed.full_name(), expected);
                assert_eq!(parsed.name(), &expected[name_offset..]);
                assert_eq!(parser.cursor.position(), input.len());
                assert_eq!(parser.stack.logical_num(), 0);
            }
        }
    }

    #[test]
    fn dynamic_operators_accept_nested_operator_class_and_template_siblings() {
        for (input, flags, expected) in [
            (
                b"??__E??_C@@YAXXZ".as_slice(),
                UNDNAME_COMPLETE,
                "void __cdecl `dynamic initializer for '`string'''(void)",
            ),
            (
                b"??__Ex@C@@YAXXZ",
                UNDNAME_COMPLETE,
                "void __cdecl C::`dynamic initializer for 'x''(void)",
            ),
            (
                b"??$?__Ex@H@@YAXXZ",
                UNDNAME_COMPLETE,
                "void __cdecl `dynamic initializer for 'x''<int>(void)",
            ),
            (
                b"??__E?x@@3HA!@YAXXZ",
                UNDNAME_COMPLETE,
                "void __cdecl `dynamic initializer for 'int x''(void)",
            ),
            (
                b"??__E?x@@3HA@@3HA",
                UNDNAME_COMPLETE,
                "int `dynamic initializer for 'int x''",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let parsed = parser.parse_symbol().expect("dynamic sibling parses");
            assert_eq!(parsed.full_name(), expected, "input {input:?}");
            assert_eq!(parser.cursor.position(), input.len(), "input {input:?}");
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn dynamic_payload_restores_nested_state_but_literal_remains_in_names() {
        let mut nested =
            MsvcParser::new(b"?x@@3HA@", UNDNAME_COMPLETE).expect("input within limit");
        nested.name_pos = 3;
        nested
            .stack
            .push("OuterStack", &mut nested.budget)
            .expect("outer stack entry");
        nested
            .names
            .push("OuterName", &mut nested.budget)
            .expect("outer name entry");
        let names_start = nested.names.logical_start();
        let names_num = nested.names.logical_num();
        let parsed = nested
            .parse_dynamic_operator_name(super::DynamicOperator::Initializer)
            .expect("nested payload parses");
        assert_eq!(parsed, "`dynamic initializer for 'int x''");
        assert_eq!(nested.cursor.position(), b"?x@@3HA@".len());
        assert_eq!(nested.stack.logical_num(), 1);
        assert_eq!(nested.stack.active_absolute_reference(0), Ok("OuterStack"));
        assert_eq!(nested.names.logical_start(), names_start);
        assert_eq!(nested.names.logical_num(), names_num);
        assert_eq!(nested.names.reference(0), Ok("OuterName"));
        assert_eq!(nested.names.reference(1), Ok("x"));
        assert_eq!(nested.depth, 0);
        assert_eq!(nested.name_pos, 3);

        let mut literal = MsvcParser::new(b"value@", UNDNAME_COMPLETE).expect("input within limit");
        literal
            .names
            .push("OuterName", &mut literal.budget)
            .expect("outer name entry");
        let parsed = literal
            .parse_dynamic_operator_name(super::DynamicOperator::AtexitDestructor)
            .expect("literal payload parses");
        assert_eq!(parsed, "`dynamic atexit destructor for 'value''");
        assert_eq!(literal.cursor.position(), 6);
        assert_eq!(literal.names.logical_num(), 2);
        assert_eq!(literal.names.reference(1), Ok("value"));
        assert_eq!(literal.stack.logical_num(), 0);

        let mut malformed =
            MsvcParser::new(b"?x@@3H!", UNDNAME_COMPLETE).expect("input within limit");
        malformed
            .stack
            .push("OuterStack", &mut malformed.budget)
            .expect("outer stack entry");
        malformed
            .names
            .push("OuterName", &mut malformed.budget)
            .expect("outer name entry");
        let prior_budget = malformed.budget.used();
        assert_eq!(
            malformed.parse_dynamic_operator_name(super::DynamicOperator::Initializer),
            Err(ParseFailure::InvalidModifier {
                offset: 6,
                found: b'!',
            })
        );
        assert_eq!(malformed.cursor.position(), b"?x@@3H!".len());
        assert_eq!(malformed.stack.logical_num(), 1);
        assert_eq!(
            malformed.stack.active_absolute_reference(0),
            Ok("OuterStack")
        );
        assert_eq!(malformed.names.logical_num(), 1);
        assert_eq!(malformed.names.reference(0), Ok("OuterName"));
        assert_eq!(malformed.names.reference(1), Ok("x"));
        assert!(malformed.budget.used() > prior_budget);
        assert_eq!(malformed.depth, 0);
    }

    #[test]
    fn dynamic_operator_budget_charges_nested_wrapper_push_and_final_result() {
        let payload = b"?x@@3HA@";
        let mut nested_measure =
            MsvcParser::new(payload, UNDNAME_COMPLETE).expect("input within limit");
        let nested_result = nested_measure
            .parse_nested_symbol()
            .expect("nested data parses");
        assert_eq!(nested_result.full_name(), "int x");
        let nested_cost = nested_measure.budget.used();

        let mut wrapper_failure =
            MsvcParser::new(payload, UNDNAME_COMPLETE).expect("input within limit");
        wrapper_failure.budget = AttemptBudget::with_limit(nested_cost);
        assert!(matches!(
            wrapper_failure.parse_dynamic_operator_name(super::DynamicOperator::Initializer),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(wrapper_failure.cursor.position(), payload.len());
        assert_eq!(wrapper_failure.budget.used(), nested_cost);
        assert_eq!(wrapper_failure.stack.logical_num(), 0);
        assert_eq!(wrapper_failure.names.logical_num(), 0);
        assert_eq!(wrapper_failure.names.reference(0), Ok("x"));

        let mut dynamic_measure =
            MsvcParser::new(payload, UNDNAME_COMPLETE).expect("input within limit");
        let dynamic_name = dynamic_measure
            .parse_dynamic_operator_name(super::DynamicOperator::Initializer)
            .expect("dynamic wrapper parses");
        let dynamic_cost = dynamic_measure.budget.used();
        assert!(dynamic_cost > nested_cost);

        let input = b"??__E?x@@3HA@@YAXXZ";
        let mut push_failure =
            MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        push_failure.budget = AttemptBudget::with_limit(dynamic_cost);
        assert!(matches!(
            push_failure.parse_symbol(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(push_failure.cursor.position(), payload.len() + 5);
        assert_eq!(push_failure.budget.used(), dynamic_cost);
        assert_eq!(push_failure.stack.logical_num(), 0);

        let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        let parsed = measured.parse_symbol().expect("full dynamic symbol parses");
        assert_eq!(
            parsed.full_name(),
            "void __cdecl `dynamic initializer for 'int x''(void)"
        );
        let full_cost = measured.budget.used();
        assert!(full_cost > dynamic_cost + dynamic_name.len());

        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        exact.budget = AttemptBudget::with_limit(full_cost);
        assert!(exact.parse_symbol().is_ok());
        assert_eq!(exact.budget.used(), full_cost);
        assert_eq!(exact.cursor.position(), input.len());

        let mut one_under = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        one_under.budget = AttemptBudget::with_limit(full_cost - 1);
        assert!(matches!(
            one_under.parse_symbol(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(one_under.cursor.position(), input.len());
        assert_eq!(one_under.stack.logical_num(), 0);
    }

    #[test]
    fn dynamic_operator_payload_failures_preserve_exact_cursor() {
        for (input, expected, position) in [
            (
                b"??__E".as_slice(),
                ParseFailure::InvalidLiteral {
                    offset: 5,
                    found: None,
                },
                5,
            ),
            (
                b"??__E!",
                ParseFailure::InvalidLiteral {
                    offset: 5,
                    found: Some(b'!'),
                },
                5,
            ),
            (
                b"??__Ex",
                ParseFailure::InvalidLiteral {
                    offset: 6,
                    found: None,
                },
                6,
            ),
            (
                b"??__E?x@@3HA",
                ParseFailure::AdvanceOutOfBounds {
                    offset: 12,
                    amount: 1,
                    len: 12,
                },
                12,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert_eq!(parser.parse_symbol(), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn multibyte_operator_failures_consume_exact_discriminators_and_restore_stack() {
        for (input, expected, position) in [
            (
                b"??_R5".as_slice(),
                ParseFailure::UnsupportedOperatorCode {
                    offset: 4,
                    found: b'5',
                },
                5,
            ),
            (
                b"??_Q",
                ParseFailure::UnsupportedOperatorCode {
                    offset: 3,
                    found: b'Q',
                },
                4,
            ),
            (
                b"??__Q",
                ParseFailure::UnsupportedOperatorCode {
                    offset: 4,
                    found: b'Q',
                },
                5,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(parser.parse_operator_method(), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        for (input, offset) in [
            (b"??_".as_slice(), 3),
            (b"??__", 4),
            (b"??_R", 4),
            (b"??_R0", 5),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(
                parser.parse_operator_method(),
                Err(ParseFailure::UnexpectedEnd { offset })
            );
            assert_eq!(parser.cursor.position(), offset);
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn special_operator_data_dispatch_uses_data_signature() {
        let mut parser = MsvcParser::new(b"??_7C@@6B@", UNDNAME_COMPLETE).expect("within limit");
        let parsed = parser
            .parse_operator_method()
            .expect("special data operator dispatch");
        assert_eq!(parsed.full_name(), "const C::`vftable'");
        assert_eq!(parsed.name(), "const C::`vftable'");
        assert_eq!(parser.cursor.position(), 9);
        assert_eq!(parser.stack.logical_num(), 0);

        let mut real =
            MsvcParser::new(b"??_7DNameNode@@6B@", UNDNAME_COMPLETE).expect("within limit");
        let parsed = real.parse_operator_method().expect("real vftable fixture");
        assert_eq!(parsed.full_name(), "const DNameNode::`vftable'");
        assert_eq!(parsed.name(), "const DNameNode::`vftable'");
        assert_eq!(real.cursor.peek(0), Some(b'@'));
        assert_eq!(real.stack.logical_num(), 0);
    }

    #[test]
    fn constructor_no_return_still_parses_return_and_argument_material() {
        let mut valid =
            MsvcParser::new(b"??0C@@QAEPAHH@Z", UNDNAME_COMPLETE).expect("input within limit");
        let parsed = valid
            .parse_operator_method()
            .expect("return datatype is consumed before suppression");
        assert_eq!(parsed.full_name(), "public: __thiscall C::C(int)");
        assert_eq!(valid.cursor.position(), 15);
        assert_eq!(valid.stack.logical_num(), 0);

        let mut malformed =
            MsvcParser::new(b"??0C@@QAE!XZ", UNDNAME_COMPLETE).expect("input within limit");
        assert_eq!(
            malformed.parse_operator_method(),
            Err(ParseFailure::InvalidDatatypeCode {
                offset: 9,
                found: b'!',
            })
        );
        assert_eq!(malformed.cursor.position(), 10);
        assert_eq!(malformed.stack.logical_num(), 0);
    }

    #[test]
    fn top_level_method_renders_member_kinds_this_modifiers_and_global_functions() {
        for (input, full, name) in [
            (
                b"?f@C@@QAEHXZ".as_slice(),
                "public: int __thiscall C::f(void)",
                "C::f(void)",
            ),
            (
                b"?f@C@@QBEHXZ",
                "public: int __thiscall C::f(void)const ",
                "C::f(void)const ",
            ),
            (
                b"?f@C@@QEAAXXZ",
                "public: void __cdecl C::f(void) __ptr64",
                "C::f(void) __ptr64",
            ),
            (
                b"?f@C@@SAHXZ",
                "public: static int __cdecl C::f(void)",
                "C::f(void)",
            ),
            (
                b"?f@C@@UAEXXZ",
                "public: virtual void __thiscall C::f(void)",
                "C::f(void)",
            ),
            (b"?global@@YAHH@Z", "int __cdecl global(int)", "global(int)"),
        ] {
            assert_top_level_method(input, UNDNAME_COMPLETE, full, name);
        }
    }

    #[test]
    fn top_level_method_applies_return_name_and_render_suppression_after_parsing() {
        assert_top_level_method(
            b"?f@C@@QAEPAHH@Z",
            crate::msvc::flags::UNDNAME_NO_FUNCTION_RETURNS,
            "public: __thiscall C::f(int)",
            "C::f(int)",
        );
        assert_top_level_method(
            b"?f@C@@QAEHXZ",
            crate::msvc::flags::UNDNAME_NAME_ONLY,
            "C::f",
            "C::f",
        );
        assert_top_level_method(
            b"?f@?$C@VFoo@@@@QEAAXXZ",
            crate::msvc::flags::UNDNAME_NAME_ONLY,
            "C<Foo>::f",
            "C<Foo>::f",
        );
        assert_top_level_method(
            b"?f@C@@QBEHXZ",
            crate::msvc::flags::UNDNAME_NO_THISTYPE,
            "public: int __thiscall C::f(void)",
            "C::f(void)",
        );
    }

    #[test]
    fn top_level_method_accepts_every_scoped_non_thunk_accmem_letter() {
        for accmem in b'A'..=b'Z' {
            if matches!(accmem, b'G' | b'H' | b'O' | b'P' | b'W' | b'X') {
                continue;
            }
            let kind = MethodKind::decode(accmem);
            let mut input = vec![b'?', b'f', b'@', b'C', b'@', b'@', accmem];
            if kind.has_this {
                input.push(b'A');
            }
            input.extend_from_slice(b"AXXZ");
            let mut parser = MsvcParser::new(&input, UNDNAME_COMPLETE).expect("input within limit");
            assert!(
                parser.parse_ordinary_method().is_ok(),
                "accmem {} must be supported",
                char::from(accmem)
            );
            assert_eq!(parser.cursor.position(), input.len());
        }
    }

    #[test]
    fn top_level_method_thunk_aliases_match_bundled_c_oracle() {
        for (code, access, name_pos) in [
            ("G", "private: ", 37),
            ("H", "private: ", 37),
            ("O", "protected: ", 39),
            ("P", "protected: ", 39),
            ("W", "public: ", 36),
            ("X", "public: ", 36),
        ] {
            let input = format!("?f@C@@{code}A@AAHXZ");
            let expected =
                format!("[thunk]:{access}virtual int __cdecl C::f`adjustor{{0}}' (void)");
            let mut parser =
                MsvcParser::new(input.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
            let parsed = parser
                .parse_ordinary_method()
                .expect("adjustor thunk alias");
            assert_eq!(parsed.full_name(), expected, "adjustor alias {code}");
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }

        for (prefix, modifier, access, name_pos) in [
            ("$0", "vtordisp{0,0}", "private: ", 37),
            ("$1", "vtordisp{0,0}", "private: ", 37),
            ("$2", "vtordisp{0,0}", "protected: ", 39),
            ("$3", "vtordisp{0,0}", "protected: ", 39),
            ("$4", "vtordisp{0,0}", "public: ", 36),
            ("$5", "vtordisp{0,0}", "public: ", 36),
            ("$R0", "vtordispex{0,0,0,0}", "private: ", 37),
            ("$R1", "vtordispex{0,0,0,0}", "private: ", 37),
            ("$R2", "vtordispex{0,0,0,0}", "protected: ", 39),
            ("$R3", "vtordispex{0,0,0,0}", "protected: ", 39),
            ("$R4", "vtordispex{0,0,0,0}", "public: ", 36),
            ("$R5", "vtordispex{0,0,0,0}", "public: ", 36),
        ] {
            let numbers = if prefix.starts_with("$R") {
                "A@A@A@A@"
            } else {
                "A@A@"
            };
            let input = format!("?f@C@@{prefix}{numbers}AAHXZ");
            let expected = format!("[thunk]:{access}virtual int __cdecl C::f`{modifier}' (void)");
            let mut parser =
                MsvcParser::new(input.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
            let parsed = parser
                .parse_ordinary_method()
                .expect("vtordisp thunk alias");
            assert_eq!(parsed.full_name(), expected, "thunk alias {prefix}");
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let input = b"?f@C@@$BA@AA";
        for (flags, expected, name_pos) in [
            (UNDNAME_COMPLETE, "[thunk]:__cdecl C::f{0{flat}}' ", 16),
            (VMP_DEMANGLE_FLAGS, "[thunk]:C::f{0{flat}}' ", 8),
            (UNDNAME_NAME_ONLY, "[thunk]:C::f{0{flat}}' ", 8),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("within limit");
            let parsed = parser.parse_ordinary_method().expect("vcall thunk");
            assert_eq!(parsed.full_name(), expected);
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let trailing = b"?f@C@@$BA@AAHXZ";
        let mut parser = MsvcParser::new(trailing, UNDNAME_COMPLETE).expect("within limit");
        let parsed = parser.parse_ordinary_method().expect("vcall thunk");
        assert_eq!(parsed.full_name(), "[thunk]:__cdecl C::f{0{flat}}' ");
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.cursor.peek(0), Some(b'H'));
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn top_level_method_thunks_preserve_signed_hex_and_suppression_order() {
        for (input, complete, vmp, name_only) in [
            (
                b"?f@C@@G?0AAHXZ".as_slice(),
                "[thunk]:private: virtual int __cdecl C::f`adjustor{-1}' (void)",
                "[thunk]:int C::f`adjustor{-1}' (void)",
                "[thunk]:C::f`adjustor{-1}' ",
            ),
            (
                b"?f@C@@$0BA@?0AAHXZ",
                "[thunk]:private: virtual int __cdecl C::f`vtordisp{16,-1}' (void)",
                "[thunk]:int C::f`vtordisp{16,-1}' (void)",
                "[thunk]:C::f`vtordisp{16,-1}' ",
            ),
            (
                b"?f@C@@$R0A@0?0BA@AAHXZ",
                "[thunk]:private: virtual int __cdecl C::f`vtordispex{0,1,-1,16}' (void)",
                "[thunk]:int C::f`vtordispex{0,1,-1,16}' (void)",
                "[thunk]:C::f`vtordispex{0,1,-1,16}' ",
            ),
        ] {
            for (flags, expected, name_pos) in [
                (UNDNAME_COMPLETE, complete, 37),
                (VMP_DEMANGLE_FLAGS, vmp, 12),
                (UNDNAME_NAME_ONLY, name_only, 8),
            ] {
                let mut parser = MsvcParser::new(input, flags).expect("within limit");
                let parsed = parser.parse_ordinary_method().expect("suppressed thunk");
                assert_eq!(parsed.full_name(), expected);
                assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
                assert_eq!(parser.cursor.position(), input.len());
                assert_eq!(parser.stack.logical_num(), 0);
            }
        }
    }

    #[test]
    fn malformed_thunk_dispatchers_numbers_flat_marker_and_calling_convention_are_exact() {
        for (input, expected, position) in [
            (
                b"?f@C@@$!tail".as_slice(),
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 7,
                    found: b'!',
                },
                8,
            ),
            (
                b"?f@C@@$R6tail",
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 8,
                    found: b'6',
                },
                9,
            ),
            (
                b"?f@C@@G",
                ParseFailure::InvalidNumberStart {
                    offset: 7,
                    found: None,
                },
                7,
            ),
            (
                b"?f@C@@$0",
                ParseFailure::InvalidNumberStart {
                    offset: 8,
                    found: None,
                },
                8,
            ),
            (
                b"?f@C@@$0A@",
                ParseFailure::InvalidNumberStart {
                    offset: 10,
                    found: None,
                },
                10,
            ),
            (
                b"?f@C@@$R0A@A@A@",
                ParseFailure::InvalidNumberStart {
                    offset: 15,
                    found: None,
                },
                15,
            ),
            (
                b"?f@C@@$B",
                ParseFailure::InvalidNumberStart {
                    offset: 8,
                    found: None,
                },
                8,
            ),
            (
                b"?f@C@@$BA@!",
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 10,
                    found: b'!',
                },
                11,
            ),
            (
                b"?f@C@@GA@A!",
                ParseFailure::InvalidCallingConvention { found: b'!' },
                11,
            ),
            (
                b"?f@C@@$0A@A@A!",
                ParseFailure::InvalidCallingConvention { found: b'!' },
                14,
            ),
            (
                b"?f@C@@$R0A@A@A@A@A!",
                ParseFailure::InvalidCallingConvention { found: b'!' },
                19,
            ),
            (
                b"?f@C@@$BA@A!",
                ParseFailure::InvalidCallingConvention { found: b'!' },
                12,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(parser.parse_ordinary_method(), Err(expected), "{input:?}");
            assert_eq!(parser.cursor.position(), position, "{input:?}");
            assert_eq!(parser.stack.logical_num(), 0, "{input:?}");
        }

        for (input, offset) in [
            (b"?f@C@@$".as_slice(), 7),
            (b"?f@C@@$R", 8),
            (b"?f@C@@$BA@", 10),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(
                parser.parse_ordinary_method(),
                Err(ParseFailure::UnexpectedEnd { offset })
            );
            assert_eq!(parser.cursor.position(), offset);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let input = b"?f@C@@$BA@A!";
        let mut suppressed = MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("within limit");
        let parsed = suppressed
            .parse_ordinary_method()
            .expect("suppressed calling convention still consumes its byte");
        assert_eq!(parsed.full_name(), "[thunk]:C::f{0{flat}}' ");
        assert_eq!(suppressed.cursor.position(), input.len());
        assert_eq!(suppressed.stack.logical_num(), 0);
    }

    #[test]
    fn operator_thunks_preserve_cast_and_no_return_source_order() {
        for (input, expected) in [
            (
                b"??BC@@GA@AAHXZ".as_slice(),
                "[thunk]:private: virtual __cdecl C::operator `adjustor{0}' int(void)",
            ),
            (
                b"??0C@@GA@AAHXZ",
                "[thunk]:private: virtual __cdecl C::C`adjustor{0}' (void)",
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            let parsed = parser
                .parse_operator_method()
                .expect("operator thunk encoding");
            assert_eq!(parsed.full_name(), expected);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn thunk_rendering_honors_exact_cumulative_budget_boundary() {
        for input in [
            b"?f@C@@GA@AAHXZ".as_slice(),
            b"?f@C@@$0A@A@AAHXZ",
            b"?f@C@@$R0A@A@A@A@AAHXZ",
            b"?f@C@@$BA@AA",
        ] {
            let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            measured
                .parse_ordinary_method()
                .expect("measure thunk parse");
            let exact = measured.budget.used();
            assert!(exact > 0);

            let mut accepted = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            accepted.budget = AttemptBudget::with_limit(exact);
            assert!(accepted.parse_ordinary_method().is_ok());
            assert_eq!(accepted.budget.used(), exact);

            let mut rejected = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            rejected.budget = AttemptBudget::with_limit(exact - 1);
            assert!(matches!(
                rejected.parse_ordinary_method(),
                Err(ParseFailure::OutputLimitExceeded { .. })
            ));
            assert_eq!(rejected.stack.logical_num(), 0);
        }
    }

    #[test]
    fn top_level_method_flags_preserve_calling_convention_and_member_render_order() {
        assert_top_level_method(
            b"?f@C@@SBHXZ",
            UNDNAME_COMPLETE,
            "public: static int __cdecl __dll_export C::f(void)",
            "C::f(void)",
        );
        assert_top_level_method(
            b"?f@C@@SAHXZ",
            crate::msvc::flags::UNDNAME_NO_LEADING_UNDERSCORES,
            "public: static int cdecl C::f(void)",
            "C::f(void)",
        );
        assert_top_level_method(
            b"?f@C@@SAHXZ",
            crate::msvc::flags::UNDNAME_NO_ACCESS_SPECIFIERS,
            "static int __cdecl C::f(void)",
            "C::f(void)",
        );
        assert_top_level_method(
            b"?f@C@@SAHXZ",
            crate::msvc::flags::UNDNAME_NO_MEMBER_TYPE,
            "public: int __cdecl C::f(void)",
            "C::f(void)",
        );
    }

    #[test]
    fn top_level_method_preserves_return_right_variadics_and_ignores_throw_material() {
        assert_top_level_method(
            b"?f@@YAP6AHH@ZXZ",
            UNDNAME_COMPLETE,
            "int (__cdecl*__cdecl f(void))(int)",
            "f(void))(int)",
        );
        assert_top_level_method(
            b"?f@@YAHHZZ",
            UNDNAME_COMPLETE,
            "int __cdecl f(int,...)",
            "f(int,...)",
        );

        let input = b"?f@@YAHH@Z()throw";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
        let parsed = parser
            .parse_ordinary_method()
            .expect("throw material is outside the parsed signature");
        assert_eq!(parsed.full_name(), "int __cdecl f(int)");
        assert_eq!(parsed.name(), "f(int)");
        assert_eq!(parser.cursor.peek(0), Some(b'('));
    }

    #[test]
    fn top_level_method_reports_typed_dispatch_failures_at_exact_offsets() {
        let mut prefix = MsvcParser::new(b"plain", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            prefix.parse_ordinary_method(),
            Err(ParseFailure::InvalidMsvcPrefix {
                offset: 0,
                found: Some(b'p'),
            })
        );
        assert_eq!(prefix.cursor.position(), 0);

        let mut operator =
            MsvcParser::new(b"??0@C@@QAE@XZ", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            operator.parse_ordinary_method(),
            Err(ParseFailure::UnsupportedTopLevelName {
                offset: 1,
                found: b'?',
            })
        );
        assert_eq!(operator.cursor.position(), 1);

        let mut data = MsvcParser::new(b"?f@@3HA", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            data.parse_ordinary_method(),
            Err(ParseFailure::UnsupportedMethodEncoding {
                offset: 4,
                found: b'3',
            })
        );
        assert_eq!(data.cursor.position(), 5);

        let mut thunk = MsvcParser::new(b"?f@C@@Gtail", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            thunk.parse_ordinary_method(),
            Err(ParseFailure::InvalidNumberStart {
                offset: 7,
                found: Some(b't'),
            })
        );
        assert_eq!(thunk.cursor.position(), 7);

        let mut malformed = MsvcParser::new(b"?f@C@@Q", UNDNAME_COMPLETE).expect("within limit");
        assert!(matches!(
            malformed.parse_ordinary_method(),
            Err(ParseFailure::UnexpectedEnd { offset: 7 })
        ));
        assert_eq!(malformed.stack.logical_num(), 0);
    }

    #[test]
    fn top_level_method_unsupported_dispatchers_preserve_required_cursor_contract() {
        for (input, expected_position) in [
            (b"??0@C@@QAE@XZ".as_slice(), 1),
            (b"?$f@H@@YAXXZ", 1),
            (b"?f@@3HA", 5),
            (b"?f@C@@$0tail", 8),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert!(parser.parse_ordinary_method().is_err());
            assert_eq!(parser.cursor.position(), expected_position);
        }
        for input in [b"?f@C@@Gtail".as_slice(), b"?f@C@@Xtail"] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("input within limit");
            assert!(parser.parse_ordinary_method().is_err());
            assert_eq!(parser.cursor.position(), 7, "thunk accmem is consumed");
        }
    }

    #[test]
    fn unified_symbol_parses_ordinary_top_level_function_templates() {
        for (input, flags, expected, name_pos, expected_name) in [
            (
                b"??$f@H@@YAXH@Z".as_slice(),
                UNDNAME_COMPLETE,
                "void __cdecl f<int>(int)",
                13,
                "f<int>(int)",
            ),
            (
                b"??$f@H@ns@@YAHH@Z",
                UNDNAME_NAME_ONLY,
                "ns::f<int>",
                0,
                "ns::f<int>",
            ),
            (
                b"??$f@$1?g@@YAHXZ@@YAXXZ",
                VMP_DEMANGLE_FLAGS,
                "void f<&int g(void)>(void)",
                5,
                "f<&int g(void)>(void)",
            ),
            (
                b"??$f@V?$C@H@@@@YAXXZ",
                UNDNAME_NAME_ONLY,
                "f<C<int> >",
                0,
                "f<C<int> >",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let parsed = parser.parse_symbol().expect("ordinary function template");
            assert_eq!(parsed.full_name(), expected, "input {input:?}");
            assert_eq!(parsed.name(), expected_name, "input {input:?}");
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.cursor.position(), input.len());
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn ordinary_top_level_function_templates_match_all_map_fixture_rows() {
        let mut matched = 0usize;
        for line in include_str!("../../tests/fixtures/msvc_corpus.tsv").lines() {
            let Some((raw, expected_full, expected_name_pos, expected_name)) =
                decode_template_fixture_row(line).expect("valid bounded TSV fixture row")
            else {
                continue;
            };
            matched += 1;
            let mut parser =
                MsvcParser::new(raw.as_bytes(), VMP_DEMANGLE_FLAGS).expect("fixture within limit");
            let parsed = parser.parse_symbol().expect("MAP function template");
            assert_eq!(parsed.full_name(), expected_full, "raw {raw}");
            assert_eq!(parsed.name(), expected_name, "raw {raw}");
            assert_eq!(
                parsed.full_name().len() - parsed.name().len(),
                expected_name_pos,
                "raw {raw}"
            );
            assert!(parser.cursor.position() <= raw.len(), "raw {raw}");
            assert_eq!(parser.stack.logical_num(), 0, "raw {raw}");
        }
        assert_eq!(matched, 28, "ordinary template fixture cardinality changed");
    }

    #[test]
    fn ordinary_function_templates_dispatch_data_and_restore_nested_name_scope() {
        let mut data = MsvcParser::new(b"??$x@H@@3HA", UNDNAME_COMPLETE).expect("within limit");
        let parsed = data.parse_symbol().expect("template data symbol");
        assert_eq!(parsed.full_name(), "int x<int>");
        assert_eq!(parsed.name(), "int x<int>");
        assert_eq!(data.cursor.position(), 11);
        assert_eq!(data.names.logical_start(), 1);
        assert_eq!(data.stack.logical_num(), 0);

        let input = b"?outer@???$f@H@@YAXXZ@YAXXZ";
        let mut nested = MsvcParser::new(input, UNDNAME_NAME_ONLY).expect("within limit");
        let parsed = nested
            .parse_symbol()
            .expect("nested template function symbol");
        assert_eq!(parsed.full_name(), "`f<int>'::outer");
        assert_eq!(nested.cursor.position(), input.len());
        assert_eq!(nested.names.logical_start(), 0);
        assert_eq!(nested.stack.logical_num(), 0);
        assert_eq!(nested.depth, 0);
    }

    #[test]
    fn ordinary_function_template_failures_preserve_cursor_and_start_mutation_timing() {
        for (input, expected, position, names_start) in [
            (
                b"??$".as_slice(),
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: None,
                },
                3,
                0,
            ),
            (
                b"??$!tail",
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: Some(b'!'),
                },
                3,
                0,
            ),
            (b"??$f@H@", ParseFailure::UnexpectedEnd { offset: 7 }, 7, 0),
            (
                b"??$f@$X@@YAXXZ",
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 8,
                    found: b'@',
                },
                8,
                1,
            ),
            (
                b"??$f@H@@!",
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 8,
                    found: b'!',
                },
                8,
                1,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(parser.parse_symbol(), Err(expected), "input {input:?}");
            assert_eq!(parser.cursor.position(), position, "input {input:?}");
            assert_eq!(parser.names.logical_start(), names_start, "input {input:?}");
            assert_eq!(parser.stack.logical_num(), 0, "input {input:?}");
        }

        let mut legacy = MsvcParser::new(b"?$f@H@@YAXXZ", UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            legacy.parse_ordinary_method(),
            Err(ParseFailure::UnsupportedTopLevelName {
                offset: 1,
                found: b'$',
            })
        );
        assert_eq!(legacy.cursor.position(), 1);
        assert_eq!(legacy.names.logical_start(), 0);
    }

    #[test]
    fn ordinary_function_template_budget_and_name_capacity_boundaries_are_inherited() {
        let input = b"??$f@H@@YAXH@Z";
        let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        measured.parse_symbol().expect("measure successful parse");
        let exact_cost = measured.budget.used();

        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        exact.budget = AttemptBudget::with_limit(exact_cost);
        assert!(exact.parse_symbol().is_ok());
        assert_eq!(exact.budget.used(), exact_cost);

        let mut one_under = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        one_under.budget = AttemptBudget::with_limit(exact_cost - 1);
        assert!(matches!(
            one_under.parse_symbol(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));
        assert_eq!(one_under.stack.logical_num(), 0);

        let mut names_full = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        names_full.names = RefArray::with_limit(0);
        assert_eq!(
            names_full.parse_symbol(),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(names_full.names.logical_start(), 0);
        assert_eq!(names_full.stack.logical_num(), 0);
    }

    #[test]
    fn unified_symbol_dispatch_matches_existing_ordinary_data_operator_rtti_and_thunks() {
        for (input, expected) in [
            (
                b"?newCol@QColorPicker@?A0x3be3cb80@@QEAAXHH@Z".as_slice(),
                "void `anonymous namespace'::QColorPicker::newCol(int,int)",
            ),
            (
                b"?InitWorkspacesCollection@CDaoWorkspace@@IAEXXZ",
                "void CDaoWorkspace::InitWorkspacesCollection(void)",
            ),
            (
                b"?Invoke@XEventSink@COleControlSite@@UAGJJABU_GUID@@KGPAUtagDISPPARAMS@@PAUtagVARIANT@@PAUtagEXCEPINFO@@PAI@Z",
                "long COleControlSite::XEventSink::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)",
            ),
            (
                b"?IsNullValue@CDaoFieldExchange@@SGHPAXK@Z",
                "int CDaoFieldExchange::IsNullValue(void *,unsigned long)",
            ),
            (
                b"??$?0VQObject@@@?$QWeakPointer@VQObject@@@@AEAA@PEAVQObject@@_N@Z",
                "QWeakPointer<class QObject>::<class QObject>::<class QObject>(class QObject *,bool)",
            ),
            (b"?x@C@@0HA", "int C::x"),
            (b"??HC@@QAEHH@Z", "int C::operator+(int)"),
            (
                b"??_R4type_info@@6B@",
                "const type_info::`RTTI Complete Object Locator'",
            ),
            (
                b"?f@C@@$0BA@?0AAHXZ",
                "[thunk]:int C::f`vtordisp{16,-1}' (void)",
            ),
            (b"??_Ctail", "`string'"),
        ] {
            let mut parser = MsvcParser::new(input, VMP_DEMANGLE_FLAGS).expect("within limit");
            let parsed = parser.parse_symbol().expect("supported unified symbol");
            assert_eq!(parsed.full_name(), expected, "input {input:?}");
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn unified_symbol_operator_lookahead_handles_truncation_high_bytes_and_templates_exactly() {
        for (input, expected, position) in [
            (
                b"".as_slice(),
                ParseFailure::InvalidMsvcPrefix {
                    offset: 0,
                    found: None,
                },
                0,
            ),
            (b"?", ParseFailure::UnexpectedEnd { offset: 1 }, 1),
            (b"??", ParseFailure::UnexpectedEnd { offset: 2 }, 2),
            (
                b"??$",
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: None,
                },
                3,
            ),
            (b"??$?", ParseFailure::UnexpectedEnd { offset: 4 }, 4),
            (
                b"??\xff",
                ParseFailure::UnsupportedOperatorCode {
                    offset: 2,
                    found: 0xff,
                },
                3,
            ),
            (
                b"??$\xff",
                ParseFailure::InvalidLiteral {
                    offset: 3,
                    found: Some(0xff),
                },
                3,
            ),
            (
                b"?f@@$!tail",
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 4,
                    found: b'$',
                },
                4,
            ),
            (b"?f@@$R", ParseFailure::UnexpectedEnd { offset: 6 }, 6),
            (
                b"?f@@$R!",
                ParseFailure::UnsupportedMethodEncoding {
                    offset: 6,
                    found: b'!',
                },
                7,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(parser.parse_symbol(), Err(expected), "input {input:?}");
            assert_eq!(parser.cursor.position(), position, "input {input:?}");
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn unified_symbol_dispatches_each_supported_dollar_thunk_family() {
        for input in [
            b"?f@C@@$0BA@?0AAHXZ".as_slice(),
            b"?f@C@@$R0A@0?0BA@AAHXZ",
            b"?f@C@@$BA@AA",
        ] {
            let mut wrapper =
                MsvcParser::new(input, UNDNAME_COMPLETE).expect("wrapper input within limit");
            let expected = wrapper
                .parse_ordinary_method()
                .expect("supported thunk family");
            let expected_cursor = wrapper.cursor.position();

            let mut unified =
                MsvcParser::new(input, UNDNAME_COMPLETE).expect("unified input within limit");
            assert_eq!(unified.parse_symbol(), Ok(expected));
            assert_eq!(unified.cursor.position(), expected_cursor);
            assert_eq!(unified.stack.logical_num(), 0);
        }
    }

    #[test]
    fn unified_symbol_rejects_flags_and_nonempty_stack_before_consuming() {
        let mut no_arguments =
            MsvcParser::new(b"?f@@YAXXZ", crate::msvc::flags::UNDNAME_NO_ARGUMENTS)
                .expect("within limit");
        no_arguments
            .stack
            .push("sentinel", &mut no_arguments.budget)
            .expect("one stack entry");
        let budget = no_arguments.budget.used();
        assert_eq!(
            no_arguments.parse_symbol(),
            Err(ParseFailure::UnsupportedNoArguments { offset: 0 })
        );
        assert_eq!(no_arguments.cursor.position(), 0);
        assert_eq!(no_arguments.stack.logical_num(), 1);
        assert_eq!(no_arguments.stack.reference(0), Ok("sentinel"));
        assert_eq!(no_arguments.budget.used(), budget);

        let mut nonempty = MsvcParser::new(b"?f@@YAXXZ", UNDNAME_COMPLETE).expect("within limit");
        nonempty
            .stack
            .push("sentinel", &mut nonempty.budget)
            .expect("one stack entry");
        let budget = nonempty.budget.used();
        assert_eq!(
            nonempty.parse_symbol(),
            Err(ParseFailure::NonEmptyTopLevelStack { num: 1 })
        );
        assert_eq!(nonempty.cursor.position(), 0);
        assert_eq!(nonempty.stack.logical_num(), 1);
        assert_eq!(nonempty.stack.reference(0), Ok("sentinel"));
        assert_eq!(nonempty.budget.used(), budget);
    }

    #[test]
    fn unified_symbol_restores_logical_stack_but_preserves_attempt_side_effects() {
        let input = b"?x@@3VFoo@@!";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_symbol(),
            Err(ParseFailure::InvalidModifier {
                offset: 11,
                found: b'!',
            })
        );
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(parser.stack.reference(0), Ok("x"));
        assert_eq!(parser.names.reference(0), Ok("x"));
        assert_eq!(parser.names.reference(1), Ok("Foo"));
        assert!(parser.budget.used() > 0);
    }

    #[test]
    fn nested_symbol_class_components_match_method_and_data_oracle_results() {
        for (input, flags, expected, expected_name) in [
            (
                b"?f@A@??g@@YAXXZ@YAXXZ".as_slice(),
                UNDNAME_COMPLETE,
                "void __cdecl `void __cdecl g(void)'::A::f(void)",
                "`void __cdecl g(void)'::A::f(void)",
            ),
            (
                b"?x@??g@@YAXXZ@3HA",
                UNDNAME_COMPLETE,
                "int `void __cdecl g(void)'::x",
                "decl g(void)'::x",
            ),
            (
                b"?x@??g@@YAXXZ@3HA",
                VMP_DEMANGLE_FLAGS,
                "int `void g(void)'::x",
                "void g(void)'::x",
            ),
            (b"?x@??g@@YAXXZ@3HA", UNDNAME_NAME_ONLY, "`g'::x", "`g'::x"),
            (
                b"?f@???HC@@QAEHH@Z@YAXXZ",
                UNDNAME_NAME_ONLY,
                "`C::operator+'::f",
                "`C::operator+'::f",
            ),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let parsed = parser
                .parse_symbol()
                .expect("valid nested symbol component");
            assert_eq!(parsed.full_name(), expected, "input {input:?}");
            assert_eq!(parsed.name(), expected_name, "input {input:?}");
            assert_eq!(parser.cursor.position(), input.len(), "input {input:?}");
            assert_eq!(parser.stack.logical_num(), 0);
            assert_eq!(parser.depth, 0);
        }
    }

    #[test]
    fn strange_immediate_templates_match_native_output_cursor_and_shared_name_pos() {
        for (input, flags, expected, name_pos) in [
            (b"?$F@H@YAXXZ".as_slice(), UNDNAME_COMPLETE, "F<int>", 0),
            (b"?$F@$0A@@YAXXZ", UNDNAME_COMPLETE, "F<0>", 0),
            (
                b"?$F@$1?g@@YAHXZ@@YAXXZ",
                UNDNAME_COMPLETE,
                "F<&int __cdecl g(void)>",
                12,
            ),
            (
                b"?$F@$1?g@@YAHXZ@@YAXXZ",
                VMP_DEMANGLE_FLAGS,
                "F<&int g(void)>",
                4,
            ),
            (b"?$F@$1?g@@YAHXZ@@YAXXZ", UNDNAME_NAME_ONLY, "F<&g>", 0),
            (b"?$F@$1?h@@3HA@@YAXXZ", UNDNAME_COMPLETE, "F<&int h>", 0),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("input within limit");
            let parsed = parser.parse_symbol().expect("strange immediate template");
            assert_eq!(parsed.full_name(), expected, "input {input:?}");
            assert_eq!(parsed.full_name().len() - parsed.name().len(), name_pos);
            assert_eq!(parser.name_pos, name_pos);
            let expected_cursor = if input.starts_with(b"?$F@$1") {
                input.len() - b"@YAXXZ".len()
            } else {
                input.len() - b"YAXXZ".len()
            };
            assert_eq!(parser.cursor.position(), expected_cursor, "input {input:?}");
            assert_eq!(parser.cursor.peek(0), input.get(expected_cursor).copied());
            assert_eq!(parser.stack.logical_num(), 0);
        }
    }

    #[test]
    fn data_and_immediate_results_inherit_shared_name_pos_without_assigning_it() {
        let mut data = MsvcParser::new(b"?x@@3HA", UNDNAME_COMPLETE).expect("within limit");
        data.name_pos = 2;
        let parsed = data.parse_symbol().expect("data symbol");
        assert_eq!(parsed.full_name(), "int x");
        assert_eq!(parsed.name(), "t x");
        assert_eq!(data.name_pos, 2);

        let mut immediate = MsvcParser::new(b"??_Ctail", UNDNAME_COMPLETE).expect("within limit");
        immediate.name_pos = 3;
        let parsed = immediate.parse_symbol().expect("immediate string operator");
        assert_eq!(parsed.full_name(), "`string'");
        assert_eq!(parsed.name(), "ring'");
        assert_eq!(immediate.name_pos, 3);
        assert_eq!(immediate.cursor.position(), 4);
    }

    #[test]
    fn strange_immediate_template_preserves_fallback_budget_and_selector_validation() {
        let mut fallback = MsvcParser::new(b"?$F@$Xtail", UNDNAME_COMPLETE).expect("within limit");
        let parsed = fallback
            .parse_symbol()
            .expect("argument failure falls back");
        assert_eq!(parsed.full_name(), "F");
        assert_eq!(fallback.cursor.position(), 6);
        assert_eq!(fallback.names.logical_num(), 0);
        assert_eq!(fallback.stack.logical_num(), 0);
        assert!(fallback.budget.used() > 0);

        let input = b"?$F@H@tail";
        let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        measured.parse_symbol().expect("measure exact budget");
        let exact_cost = measured.budget.used();
        let mut exact = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        exact.budget = AttemptBudget::with_limit(exact_cost);
        assert!(exact.parse_symbol().is_ok());
        assert_eq!(exact.budget.used(), exact_cost);
        let mut one_under = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        one_under.budget = AttemptBudget::with_limit(exact_cost - 1);
        assert!(matches!(
            one_under.parse_symbol(),
            Err(ParseFailure::OutputLimitExceeded { .. })
        ));

        let mut invalid_selector =
            MsvcParser::new(b"?$F@H@tail", UNDNAME_COMPLETE).expect("within limit");
        invalid_selector.name_pos = 7;
        assert_eq!(
            invalid_selector.parse_symbol(),
            Err(ParseFailure::FunctionNameValidation(
                super::FunctionNameError::SelectorOutOfBounds {
                    selector_start: 7,
                    len: 6,
                }
            ))
        );
        assert_eq!(invalid_selector.name_pos, 7);
        assert_eq!(invalid_selector.cursor.position(), 6);
    }

    #[test]
    fn strange_immediate_template_malformed_literals_fallback_and_high_tail_are_cursor_exact() {
        for (input, expected, position) in [
            (
                b"?$".as_slice(),
                ParseFailure::InvalidLiteral {
                    offset: 2,
                    found: None,
                },
                2,
            ),
            (
                b"?$!",
                ParseFailure::InvalidLiteral {
                    offset: 2,
                    found: Some(b'!'),
                },
                2,
            ),
            (
                b"?$\xff",
                ParseFailure::InvalidLiteral {
                    offset: 2,
                    found: Some(0xff),
                },
                2,
            ),
        ] {
            let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
            assert_eq!(parser.parse_symbol(), Err(expected));
            assert_eq!(parser.cursor.position(), position);
            assert_eq!(parser.stack.logical_num(), 0);
        }

        let mut fallback = MsvcParser::new(b"?$F@", UNDNAME_COMPLETE).expect("within limit");
        let parsed = fallback
            .parse_symbol()
            .expect("unterminated empty arguments render void");
        assert_eq!(parsed.full_name(), "F<void>");
        assert_eq!(fallback.cursor.position(), 4);

        let mut high_tail =
            MsvcParser::new(b"?$F@H@\xfftail", UNDNAME_COMPLETE).expect("within limit");
        let parsed = high_tail.parse_symbol().expect("high tail is ignored");
        assert_eq!(parsed.full_name(), "F<int>");
        assert_eq!(high_tail.cursor.position(), 6);
        assert_eq!(high_tail.cursor.peek(0), Some(0xff));
    }

    #[test]
    fn strange_immediate_template_restores_logical_tables_but_keeps_high_water_and_budget() {
        let mut parser = MsvcParser::new(b"?$F@H@tail", UNDNAME_COMPLETE).expect("within limit");
        parser
            .names
            .push("OuterName", &mut parser.budget)
            .expect("name seed");
        parser
            .stack
            .push("HistoricalStack", &mut parser.budget)
            .expect("stack seed");
        parser.stack.restore_num(0).expect("historical stack");
        let names_num = parser.names.logical_num();
        let names_start = parser.names.logical_start();
        let prior_budget = parser.budget.used();

        let parsed = parser.parse_symbol().expect("strange template");
        assert_eq!(parsed.full_name(), "F<int>");
        assert_eq!(parser.names.logical_num(), names_num);
        assert_eq!(parser.names.logical_start(), names_start);
        assert_eq!(parser.names.reference(0), Ok("OuterName"));
        assert_eq!(parser.stack.logical_num(), 0);
        assert_eq!(parser.stack.reference(0), Ok("HistoricalStack"));
        assert!(parser.budget.used() > prior_budget);
    }

    #[test]
    fn dollar_one_nested_method_assigns_shared_name_pos_while_nested_data_preserves_it() {
        for (input, flags, expected) in [
            (b"$1?g@@YAHXZ".as_slice(), UNDNAME_COMPLETE, 12),
            (b"$1?g@@YAHXZ", VMP_DEMANGLE_FLAGS, 4),
            (b"$1?g@@YAHXZ", UNDNAME_NAME_ONLY, 0),
        ] {
            let mut parser = MsvcParser::new(input, flags).expect("within limit");
            assert!(parser.parse_datatype(None, false).is_ok());
            assert_eq!(parser.name_pos, expected);
        }

        let mut data = MsvcParser::new(b"$1?h@@3HA", UNDNAME_COMPLETE).expect("within limit");
        data.name_pos = 3;
        assert!(data.parse_datatype(None, false).is_ok());
        assert_eq!(data.name_pos, 3);
    }

    #[test]
    fn nested_symbol_component_restores_outer_stack_and_logical_names() {
        let input = b"??g@@YAXXZ@";
        let mut parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        parser
            .stack
            .push("Inner", &mut parser.budget)
            .expect("outer stack entry");
        parser
            .names
            .push("OuterName", &mut parser.budget)
            .expect("outer name entry");
        let names_start = parser.names.logical_start();
        let names_num = parser.names.logical_num();

        assert_eq!(parser.collect_class_components(0), Ok(()));
        assert_eq!(parser.cursor.position(), input.len());
        assert_eq!(parser.stack.logical_num(), 2);
        assert_eq!(parser.stack.active_absolute_reference(0), Ok("Inner"));
        assert_eq!(
            parser.stack.active_absolute_reference(1),
            Ok("`void __cdecl g(void)'")
        );
        assert_eq!(parser.names.logical_start(), names_start);
        assert_eq!(parser.names.logical_num(), names_num);
        assert_eq!(parser.names.reference(0), Ok("OuterName"));
        assert_eq!(parser.names.reference(1), Ok("g"));
    }

    #[test]
    fn nested_symbol_failure_restores_outer_stack_and_logical_names_after_consumption() {
        let mut parser = MsvcParser::new(b"??!", UNDNAME_COMPLETE).expect("within limit");
        parser
            .stack
            .push("Outer", &mut parser.budget)
            .expect("outer stack entry");
        parser
            .names
            .push("Name", &mut parser.budget)
            .expect("outer name entry");
        let budget = parser.budget.used();

        assert_eq!(
            parser.collect_class_components(0),
            Err(ParseFailure::InvalidLiteral {
                offset: 2,
                found: Some(b'!'),
            })
        );
        assert_eq!(parser.cursor.position(), 2);
        assert_eq!(parser.stack.logical_num(), 1);
        assert_eq!(parser.stack.active_absolute_reference(0), Ok("Outer"));
        assert_eq!(parser.names.logical_start(), 0);
        assert_eq!(parser.names.logical_num(), 1);
        assert_eq!(parser.names.reference(0), Ok("Name"));
        assert!(parser.budget.used() >= budget);
        assert_eq!(parser.depth, 0);
    }

    fn wrap_dynamic_symbol(mut nested: String, levels: usize) -> String {
        for _ in 0..levels {
            let mut outer = String::new();
            outer.push_str("??__E");
            outer.push_str(&nested);
            outer.push_str("@@YAXXZ");
            nested = outer;
        }
        nested
    }

    fn wrap_nested_symbol(mut nested: String, levels: usize) -> String {
        for _ in 0..levels {
            let mut outer = String::new();
            outer.push_str("?f@?");
            outer.push_str(&nested);
            outer.push_str("@YA@XZ");
            nested = outer;
        }
        nested
    }

    #[test]
    fn dynamic_symbols_share_combined_symbol_and_datatype_depth_limit() {
        let exact = wrap_dynamic_symbol(String::from("?g@@YA@XZ"), MAX_NESTING_DEPTH - 1);
        let mut parser = MsvcParser::new(exact.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert!(parser.parse_symbol().is_ok());
        assert_eq!(parser.cursor.position(), exact.len());
        assert_eq!(parser.depth, 0);

        let over = wrap_dynamic_symbol(String::from("?g@@YA@XZ"), MAX_NESTING_DEPTH);
        let mut parser = MsvcParser::new(over.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_symbol(),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 0);

        let exact_datatype = format!("?g@@YA{}HXZ", "PA".repeat(MAX_NESTING_DEPTH - 2));
        let exact_datatype = wrap_dynamic_symbol(exact_datatype, 1);
        let mut parser =
            MsvcParser::new(exact_datatype.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert!(parser.parse_symbol().is_ok());
        assert_eq!(parser.depth, 0);

        let over_datatype = format!("?g@@YA{}HXZ", "PA".repeat(MAX_NESTING_DEPTH - 1));
        let over_datatype = wrap_dynamic_symbol(over_datatype, 1);
        let mut parser =
            MsvcParser::new(over_datatype.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_symbol(),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn nested_symbols_share_the_datatype_nesting_limit() {
        let exact_nested = wrap_nested_symbol("?g@@YA@XZ".to_owned(), MAX_NESTING_DEPTH - 1);
        let mut parser =
            MsvcParser::new(exact_nested.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        let parsed = parser.parse_symbol();
        assert!(parsed.is_ok(), "exact nested depth failed: {parsed:?}");
        assert_eq!(parser.cursor.position(), exact_nested.len());
        assert_eq!(parser.depth, 0);

        let over_nested = wrap_nested_symbol("?g@@YA@XZ".to_owned(), MAX_NESTING_DEPTH);
        let mut parser =
            MsvcParser::new(over_nested.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_symbol(),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 0);

        let mut exact_datatype = String::from("?g@@YA");
        for _ in 0..MAX_NESTING_DEPTH - 2 {
            exact_datatype.push_str("PA");
        }
        exact_datatype.push_str("HXZ");
        let exact_datatype = wrap_nested_symbol(exact_datatype, 1);
        let mut parser =
            MsvcParser::new(exact_datatype.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert!(parser.parse_symbol().is_ok());
        assert_eq!(parser.depth, 0);

        let mut over_datatype = String::from("?g@@YA");
        for _ in 0..MAX_NESTING_DEPTH - 1 {
            over_datatype.push_str("PA");
        }
        over_datatype.push_str("HXZ");
        let over_datatype = wrap_nested_symbol(over_datatype, 1);
        let mut parser =
            MsvcParser::new(over_datatype.as_bytes(), UNDNAME_COMPLETE).expect("within limit");
        assert_eq!(
            parser.parse_symbol(),
            Err(ParseFailure::NestingLimitExceeded {
                attempted: MAX_NESTING_DEPTH + 1,
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert_eq!(parser.depth, 0);
        assert_eq!(parser.stack.logical_num(), 0);
    }

    #[test]
    fn nested_symbol_component_budget_accepts_exact_and_rejects_one_under() {
        let input = b"??g@@YA@XZ@";
        let mut measured = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        measured
            .collect_class_components(0)
            .expect("baseline nested component");
        let exact = measured.budget.used();

        let mut exact_parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        exact_parser.budget = AttemptBudget::with_limit(exact);
        assert_eq!(exact_parser.collect_class_components(0), Ok(()));
        assert_eq!(exact_parser.budget.used(), exact);
        assert_eq!(exact_parser.cursor.position(), input.len());

        let limit = exact.checked_sub(1).expect("nested parse allocates output");
        let mut over_parser = MsvcParser::new(input, UNDNAME_COMPLETE).expect("within limit");
        over_parser.budget = AttemptBudget::with_limit(limit);
        assert!(matches!(
            over_parser.collect_class_components(0),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: _,
                limit: found_limit,
            }) if found_limit == limit
        ));
        assert_eq!(over_parser.cursor.position(), input.len() - 1);
        assert_eq!(over_parser.stack.logical_num(), 0);
        assert_eq!(over_parser.names.logical_num(), 0);
        assert_eq!(over_parser.names.reference(0), Ok("g"));
        assert_eq!(over_parser.depth, 0);
    }
}
