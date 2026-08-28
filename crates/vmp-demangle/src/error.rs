use crate::function_name::FunctionNameError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseFailure {
    InvalidMsvcPrefix {
        offset: usize,
        found: Option<u8>,
    },
    UnsupportedTopLevelName {
        offset: usize,
        found: u8,
    },
    InvalidOperatorPrefix {
        offset: usize,
        found: Option<u8>,
    },
    UnsupportedOperatorCode {
        offset: usize,
        found: u8,
    },
    UnsupportedMethodEncoding {
        offset: usize,
        found: u8,
    },
    UnsupportedNoArguments {
        offset: usize,
    },
    NonEmptyTopLevelStack {
        num: usize,
    },
    FunctionNameValidation(FunctionNameError),
    InputLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    NestingLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    UnexpectedEnd {
        offset: usize,
    },
    AdvanceOutOfBounds {
        offset: usize,
        amount: usize,
        len: usize,
    },
    InvalidNumberStart {
        offset: usize,
        found: Option<u8>,
    },
    MissingNumberTerminator {
        offset: usize,
        found: Option<u8>,
    },
    NumberOverflow {
        start: usize,
        offset: usize,
        max: u32,
    },
    InvalidArrayDimensionCount {
        offset: usize,
    },
    NegativeArrayDimensionCount {
        offset: usize,
        value: i32,
    },
    ArrayDimensionLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    ArgumentLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    ArgumentCollectionAllocationFailed {
        additional: usize,
    },
    InvalidArgumentListTerminator {
        offset: usize,
        found: u8,
    },
    InvalidArgumentDelimiter {
        open: u8,
        close: u8,
    },
    InvalidModifier {
        offset: usize,
        found: u8,
    },
    InvalidDatatypeCode {
        offset: usize,
        found: u8,
    },
    UnsupportedDatatypeForm {
        offset: usize,
        found: u8,
        introducer: &'static str,
    },
    MissingParameterTypeReferences {
        offset: usize,
        digit: u8,
    },
    InvalidCallingConvention {
        found: u8,
    },
    InvalidLiteral {
        offset: usize,
        found: Option<u8>,
    },
    InvalidLiteralRange {
        start: usize,
        end: usize,
    },
    ReferenceIndexOverflow {
        start: usize,
        index: usize,
    },
    ReferenceOutOfHighWater {
        start: usize,
        index: usize,
        max: usize,
    },
    InvalidReferenceRestore {
        requested: usize,
        max: usize,
    },
    InvalidReferenceStart {
        requested: usize,
        max: usize,
    },
    ReferenceLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    ReferenceStateCorrupt {
        index: usize,
        slots_len: usize,
        max: usize,
    },
    ReferenceAllocationFailed {
        additional: usize,
    },
    UnsupportedClassComponent {
        offset: usize,
        found: u8,
    },
    EmptyClass {
        offset: usize,
    },
    ActiveReferenceOutOfRange {
        index: usize,
        num: usize,
    },
    ActiveReferenceStateCorrupt {
        index: usize,
        num: usize,
        slots_len: usize,
    },
    OutputLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    OutputAllocationFailed {
        additional: usize,
    },
}
