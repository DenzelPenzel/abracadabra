use crate::function_name::FunctionName;
use crate::limits::{
    MAX_BACKREFERENCES, MAX_COMPONENTS, MAX_INPUT_BYTES, MAX_NESTING_DEPTH, MAX_OUTPUT_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Failure {
    InvalidPrefix {
        offset: usize,
        found: Option<u8>,
    },
    UnexpectedEnd {
        offset: usize,
    },
    InvalidSourceName {
        offset: usize,
        found: Option<u8>,
    },
    NumberOverflow {
        start: usize,
        offset: usize,
    },
    SourceNamePastEnd {
        offset: usize,
        length: usize,
        remaining: usize,
    },
    MissingNestedTerminator {
        offset: usize,
        found: Option<u8>,
    },
    EmptyNestedName {
        offset: usize,
    },
    UnsupportedName {
        offset: usize,
        found: Option<u8>,
    },
    UnsupportedType {
        offset: usize,
        found: u8,
    },
    InvalidSubstitution {
        offset: usize,
        found: Option<u8>,
    },
    SubstitutionOverflow {
        start: usize,
        offset: usize,
    },
    SubstitutionOutOfRange {
        offset: usize,
        index: usize,
        available: usize,
    },
    InvalidTemplateArgument {
        offset: usize,
        found: Option<u8>,
    },
    TemplateParameterOverflow {
        start: usize,
        offset: usize,
    },
    TemplateParameterOutOfRange {
        offset: usize,
        index: usize,
        available: usize,
    },
    InvalidArrayDimension {
        offset: usize,
        found: Option<u8>,
    },
    BackreferenceLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    UnsupportedOperator {
        offset: usize,
        first: Option<u8>,
        second: Option<u8>,
    },
    VoidMixedWithArguments {
        offset: usize,
    },
    InputLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    OutputLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    BudgetExceeded {
        attempted: usize,
        limit: usize,
    },
    ComponentLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    NestingLimitExceeded {
        attempted: usize,
        limit: usize,
    },
    AllocationFailed {
        additional: usize,
    },
    InvalidUtf8 {
        offset: usize,
    },
    InvalidFunctionName,
}

#[derive(Clone, Copy)]
struct Limits {
    input: usize,
    output: usize,
    budget: usize,
    components: usize,
    backreferences: usize,
    depth: usize,
    initial_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            input: MAX_INPUT_BYTES,
            output: MAX_OUTPUT_BYTES,
            budget: MAX_OUTPUT_BYTES,
            components: MAX_COMPONENTS,
            backreferences: MAX_BACKREFERENCES,
            depth: MAX_NESTING_DEPTH,
            initial_depth: 0,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestLimits {
    output: usize,
    budget: usize,
    components: usize,
    backreferences: usize,
    depth: usize,
    initial_depth: usize,
}

#[cfg(test)]
impl Default for TestLimits {
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            output: limits.output,
            budget: limits.budget,
            components: limits.components,
            backreferences: limits.backreferences,
            depth: limits.depth,
            initial_depth: limits.initial_depth,
        }
    }
}

#[derive(Clone, Copy)]
struct Component<'a> {
    bytes: &'a [u8],
    offset: usize,
    template_args: Option<(usize, usize)>,
    destructor: bool,
    conversion: Option<ConversionTarget>,
}

#[derive(Clone, Copy)]
enum ConversionTarget {
    Type(TypeId),
    SelfTemplateParam(usize),
}

type TypeId = usize;
type ExprId = usize;

#[derive(Clone, Copy)]
enum TemplateArgId {
    Type(TypeId),
    Expr(ExprId),
}

#[derive(Clone, Copy)]
enum ExprNode<'a> {
    IntegralLiteral {
        ty: TypeId,
        digits: &'a [u8],
        offset: usize,
        negative: bool,
    },
    FloatingLiteral {
        ty: TypeId,
        digits: &'a [u8],
        negative: bool,
    },
    Cast {
        ty: TypeId,
        operand: ExprId,
    },
    Binary {
        operator: BinaryOperator,
        left: ExprId,
        right: ExprId,
    },
    Unary {
        operator: UnaryOperator,
        operand: ExprId,
    },
    ExternalName {
        components_start: usize,
        components_end: usize,
        arguments: Option<(usize, usize)>,
        const_this: bool,
    },
    ExternalLocalName {
        scope_components_start: usize,
        scope_components_end: usize,
        scope_arguments_start: usize,
        scope_arguments_end: usize,
        scope_const_this: bool,
        entity_components_start: usize,
        entity_components_end: usize,
    },
}

#[derive(Clone, Copy)]
enum BinaryOperator {
    Add,
    Greater,
}

#[derive(Clone, Copy)]
enum UnaryOperator {
    SizeOf,
    Negate,
}

#[derive(Clone, Copy)]
enum TypeNode {
    Void,
    Int,
    Char,
    Builtin(&'static str),
    Named {
        start: usize,
        end: usize,
    },
    Standard(&'static str),
    VendorQualifier {
        qualifier: usize,
        inner: TypeId,
    },
    AppliedTemplate {
        template: TypeId,
        arguments_start: usize,
        arguments_end: usize,
    },
    Array {
        dimension: ArrayDimension,
        element: TypeId,
    },
    Function {
        return_type: TypeId,
        arguments_start: usize,
        arguments_end: usize,
    },
    MemberPointer {
        class: TypeId,
        member: TypeId,
    },
    LocalName(ExprId),
    Modified {
        kind: Modifier,
        inner: TypeId,
    },
}

#[derive(Clone, Copy)]
enum ArrayDimension {
    Absent,
    Number(usize),
    Expression(ExprId),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Modifier {
    Pointer,
    Reference,
    Const,
    Volatile,
    Restrict,
}

impl Modifier {
    fn suffix(self) -> &'static str {
        match self {
            Self::Pointer => "*",
            Self::Reference => "&",
            Self::Const => " const",
            Self::Volatile => " volatile",
            Self::Restrict => " restrict",
        }
    }

    fn is_cv(self) -> bool {
        matches!(self, Self::Const | Self::Volatile | Self::Restrict)
    }
}

#[derive(Clone, Copy)]
enum ModifierSegment {
    Single(Modifier),
    Cv { start: usize, end: usize },
}

#[derive(Clone, Copy)]
enum TypeRenderPart<'input> {
    Text(&'static str),
    Bytes(&'input [u8]),
    Component(Component<'input>),
    Decimal(usize),
}

struct ParsedName<'input> {
    components: Vec<Component<'input>>,
    const_this: bool,
    arena_range: Option<(usize, usize)>,
    template_scope: Option<(usize, usize)>,
}

struct ParsedFunctionType {
    return_type: Option<TypeId>,
    arguments: Vec<TypeId>,
}

struct LocalNamePart<'input> {
    name: ParsedName<'input>,
    function: Option<ParsedFunctionType>,
}

enum DeclaratorInvocation<'function> {
    NamedFunction(Option<&'function ParsedFunctionType>),
    StandaloneType(TypeId),
}

#[derive(Clone, Copy)]
enum DeclaratorWork<'work, 'input> {
    Type {
        type_id: TypeId,
        depth: usize,
    },
    Components {
        components: &'work [Component<'input>],
        depth: usize,
    },
    StoredComponents {
        start: usize,
        end: usize,
        depth: usize,
    },
    FunctionArguments {
        start: usize,
        end: usize,
        depth: usize,
    },
    TemplateArguments {
        start: usize,
        end: usize,
        depth: usize,
    },
    Expression {
        expr_id: ExprId,
        depth: usize,
    },
    Types {
        types: &'work [TypeId],
        depth: usize,
    },
}

struct AttemptBudget {
    used: usize,
    limit: usize,
}

impl AttemptBudget {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn preflight(&self, additional: usize) -> Result<usize, Failure> {
        let attempted = self
            .used
            .checked_add(additional)
            .ok_or(Failure::BudgetExceeded {
                attempted: usize::MAX,
                limit: self.limit,
            })?;
        if attempted > self.limit {
            return Err(Failure::BudgetExceeded {
                attempted,
                limit: self.limit,
            });
        }
        Ok(attempted)
    }

    fn commit(&mut self, attempted: usize) {
        self.used = attempted;
    }
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    limits: Limits,
    component_count: usize,
    depth: usize,
    budget: AttemptBudget,
    types: Vec<TypeNode>,
    function_args: Vec<TypeId>,
    type_name_components: Vec<Component<'a>>,
    substitutions: Vec<TypeId>,
    template_args: Vec<TemplateArgId>,
    expressions: Vec<ExprNode<'a>>,
    in_progress_template_scopes: Vec<Vec<TemplateArgId>>,
    active_template_scope: Option<(usize, usize)>,
}

pub(super) fn demangle(input: &[u8]) -> Result<FunctionName, Failure> {
    parse_with_limits(input, Limits::default())
}

#[cfg(test)]
fn demangle_with_limits(input: &[u8], limits: TestLimits) -> Result<FunctionName, Failure> {
    parse_with_limits(
        input,
        Limits {
            output: limits.output,
            budget: limits.budget,
            components: limits.components,
            backreferences: limits.backreferences,
            depth: limits.depth,
            initial_depth: limits.initial_depth,
            ..Limits::default()
        },
    )
}

fn parse_with_limits(input: &[u8], limits: Limits) -> Result<FunctionName, Failure> {
    if input.len() > limits.input {
        return Err(Failure::InputLimitExceeded {
            attempted: input.len(),
            limit: limits.input,
        });
    }

    let initial_depth = limits.initial_depth;
    let budget = AttemptBudget::new(limits.budget);
    let mut parser = Parser {
        input,
        position: 0,
        limits,
        component_count: 0,
        depth: initial_depth,
        budget,
        types: Vec::new(),
        function_args: Vec::new(),
        type_name_components: Vec::new(),
        substitutions: Vec::new(),
        template_args: Vec::new(),
        expressions: Vec::new(),
        in_progress_template_scopes: Vec::new(),
        active_template_scope: None,
    };
    if input.get(..4) == Some(b"_ZTI") {
        parser.position = 4;
        parser.parse_standalone_type("typeinfo for ")
    } else if input.get(..4) == Some(b"_ZGV") {
        parser.position = 4;
        parser.parse_prefixed_name("guard variable for ")
    } else if input.get(..2) == Some(b"_Z") {
        parser.parse_mangled_name()
    } else if input.get(..8) == Some(b"_GLOBAL_")
        && matches!(input.get(8), Some(b'.' | b'_' | b'$'))
        && matches!(input.get(9), Some(b'I' | b'D'))
        && input.get(10) == Some(&b'_')
    {
        let prefix = if input.get(9) == Some(&b'I') {
            "global constructors keyed to "
        } else {
            "global destructors keyed to "
        };
        parser.position = 11;
        parser.parse_global_key(prefix)
    } else {
        parser.parse_standalone_type("")
    }
}

impl<'a> Parser<'a> {
    fn parse_prefixed_name(&mut self, prefix: &'static str) -> Result<FunctionName, Failure> {
        let name = self.parse_name()?;
        if self.position != self.input.len() {
            let found = self.byte().ok_or(Failure::UnexpectedEnd {
                offset: self.position,
            })?;
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: Some(found),
            });
        }
        self.validate_component_template_args(&name.components, 0)?;
        self.validate_declarator_capabilities(DeclaratorInvocation::NamedFunction(None))?;
        self.render(prefix, name, None)
    }

    fn parse_global_key(&mut self, prefix: &'static str) -> Result<FunctionName, Failure> {
        if self
            .input
            .get(self.position..self.position.saturating_add(2))
            == Some(b"_Z")
        {
            return self.parse_mangled_name_with_prefix(prefix);
        }
        let bytes = self
            .input
            .get(self.position..)
            .ok_or(Failure::InvalidFunctionName)?;
        if bytes.is_empty() {
            return Err(Failure::InvalidFunctionName);
        }
        let component = Component {
            bytes,
            offset: self.position,
            template_args: None,
            destructor: false,
            conversion: None,
        };
        self.add_component()?;
        self.validate_utf8(component)?;
        self.position = self.input.len();
        let output_len = checked_output_add(prefix.len(), bytes.len(), self.limits.output)?;
        let budget_used = self.budget.preflight(output_len)?;
        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| Failure::AllocationFailed {
                additional: output_len,
            })?;
        self.budget.commit(budget_used);
        output.push_str(prefix);
        self.push_component_text(&mut output, component)?;
        FunctionName::new(output, 0).map_err(|_| Failure::InvalidFunctionName)
    }

    fn parse_standalone_type(&mut self, prefix: &'static str) -> Result<FunctionName, Failure> {
        let ty = self.parse_type()?;
        if self.position != self.input.len() {
            let found = self.byte().ok_or(Failure::UnexpectedEnd {
                offset: self.position,
            })?;
            return Err(Failure::UnsupportedType {
                offset: self.position,
                found,
            });
        }
        self.validate_declarator_capabilities(DeclaratorInvocation::StandaloneType(ty))?;
        self.render_standalone_type(prefix, ty)
    }

    fn parse_mangled_name(&mut self) -> Result<FunctionName, Failure> {
        self.parse_mangled_name_with_prefix("")
    }

    fn parse_mangled_name_with_prefix(
        &mut self,
        prefix: &'static str,
    ) -> Result<FunctionName, Failure> {
        self.expect_prefix_byte(b'_')?;
        self.expect_prefix_byte(b'Z')?;
        if self.byte() == Some(b'Z') {
            return self.parse_local_name_with_prefix(prefix);
        }
        let name = self.parse_name()?;
        self.active_template_scope = name.template_scope;

        let function_name_is_template = name.components.last().is_some_and(|component| {
            component.template_args.is_some() && component.conversion.is_none()
        });
        let arguments = if self.position == self.input.len() {
            None
        } else {
            Some(self.parse_bare_function_type(function_name_is_template)?)
        };
        if self.position != self.input.len() {
            let found = self.byte().ok_or(Failure::UnexpectedEnd {
                offset: self.position,
            })?;
            return Err(Failure::UnsupportedType {
                offset: self.position,
                found,
            });
        }

        self.validate_component_template_args(&name.components, 0)?;
        self.validate_declarator_capabilities(DeclaratorInvocation::NamedFunction(
            arguments.as_ref(),
        ))?;

        self.render(prefix, name, arguments.as_ref())
    }

    fn expect_prefix_byte(&mut self, expected: u8) -> Result<(), Failure> {
        let found = self.byte();
        if found != Some(expected) {
            return Err(Failure::InvalidPrefix {
                offset: self.position,
                found,
            });
        }
        self.position += 1;
        Ok(())
    }

    fn parse_local_name_with_prefix(
        &mut self,
        prefix: &'static str,
    ) -> Result<FunctionName, Failure> {
        let original_depth = self.depth;
        let result = self.parse_local_name_chain(prefix);
        self.depth = original_depth;
        result
    }

    fn parse_local_name_chain(&mut self, prefix: &'static str) -> Result<FunctionName, Failure> {
        let mut levels = 0usize;
        while self.byte() == Some(b'Z') {
            self.enter_depth()?;
            self.add_component()?;
            self.position += 1;
            levels = levels.checked_add(1).ok_or(Failure::NestingLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.depth,
            })?;
        }
        if levels == 0 {
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: self.byte(),
            });
        }

        let scope_name = self.parse_name()?;
        self.active_template_scope = scope_name.template_scope;
        let has_return_type = scope_name.components.last().is_some_and(|component| {
            component.template_args.is_some() && component.conversion.is_none()
        });
        let mut scope_function =
            self.parse_bare_function_type_until(has_return_type, Some(b'E'))?;
        scope_function.return_type = None;
        if self.byte() != Some(b'E') {
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;

        let part_count = levels
            .checked_add(1)
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if part_count > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: part_count,
                limit: self.limits.components,
            });
        }
        let mut parts = Vec::new();
        parts
            .try_reserve_exact(part_count)
            .map_err(|_| Failure::AllocationFailed {
                additional: part_count,
            })?;
        parts.push(LocalNamePart {
            name: scope_name,
            function: Some(scope_function),
        });

        for level in 0..levels {
            let final_part = level + 1 == levels;
            let substitution_checkpoint = self.substitutions.len();
            let entity_name = self.parse_local_entity_name()?;
            self.substitutions.truncate(substitution_checkpoint);
            if substitution_checkpoint == 0 {
                if let Some((start, scope_end)) =
                    parts.first().and_then(|part| part.name.arena_range)
                {
                    let end = start.checked_add(1).ok_or(Failure::InvalidFunctionName)?;
                    if end > scope_end {
                        return Err(Failure::InvalidFunctionName);
                    }
                    let prefix = self.push_type_node(TypeNode::Named { start, end })?;
                    self.add_substitution(prefix)?;
                }
            }
            self.active_template_scope = entity_name.template_scope;
            let at_boundary = if final_part {
                self.position == self.input.len()
            } else {
                self.byte() == Some(b'E')
            };
            let entity_function = if at_boundary {
                None
            } else {
                let entity_is_template = entity_name.components.last().is_some_and(|component| {
                    component.template_args.is_some() && component.conversion.is_none()
                });
                if entity_is_template {
                    return Err(Failure::UnsupportedName {
                        offset: self.position,
                        found: self.byte(),
                    });
                }
                Some(self.parse_bare_function_type_until(false, (!final_part).then_some(b'E'))?)
            };
            if !final_part && entity_function.is_none() {
                return Err(Failure::UnsupportedName {
                    offset: self.position,
                    found: self.byte(),
                });
            }
            if !final_part {
                if self.byte() != Some(b'E') {
                    return Err(Failure::UnsupportedName {
                        offset: self.position,
                        found: self.byte(),
                    });
                }
                self.position += 1;
            }
            parts.push(LocalNamePart {
                name: entity_name,
                function: entity_function,
            });
        }
        if self.position != self.input.len() {
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: self.byte(),
            });
        }

        for part in &parts {
            self.validate_component_template_args(&part.name.components, 0)?;
            self.validate_declarator_capabilities(DeclaratorInvocation::NamedFunction(
                part.function.as_ref(),
            ))?;
        }
        self.render_local_name(prefix, &parts)
    }

    fn parse_local_entity_name(&mut self) -> Result<ParsedName<'a>, Failure> {
        let name = if self.byte() == Some(b's') {
            let offset = self.position;
            self.position += 1;
            let component = Component {
                bytes: b"string literal",
                offset,
                template_args: None,
                destructor: false,
                conversion: None,
            };
            self.add_component()?;
            let mut components = self.component_vec()?;
            self.push_existing_component(&mut components, component)?;
            ParsedName {
                components,
                const_this: false,
                arena_range: None,
                template_scope: None,
            }
        } else {
            self.parse_name()?
        };
        self.parse_discriminator()?;
        Ok(name)
    }

    fn parse_name(&mut self) -> Result<ParsedName<'a>, Failure> {
        match self.byte() {
            Some(b'N') => self.parse_nested_name(),
            Some(b'S') if self.peek(1) == Some(b't') => {
                self.position += 2;
                let mut components = self.component_vec()?;
                self.push_component(&mut components, self.standard_component())?;
                let component = if self.byte().is_some_and(|byte| byte.is_ascii_lowercase()) {
                    self.parse_operator_name_with_template_args(&components)?
                } else {
                    self.parse_source_name_with_template_args(&components)?
                };
                self.push_existing_component(&mut components, component)?;
                Ok(ParsedName {
                    components,
                    const_this: false,
                    arena_range: None,
                    template_scope: component.template_args,
                })
            }
            Some(b'L') => {
                self.position += 1;
                let mut components = self.component_vec()?;
                let component = self.parse_source_name()?;
                self.parse_discriminator()?;
                self.push_existing_component(&mut components, component)?;
                Ok(ParsedName {
                    components,
                    const_this: false,
                    arena_range: None,
                    template_scope: None,
                })
            }
            Some(byte) if byte.is_ascii_digit() => {
                let mut components = self.component_vec()?;
                let component = self.parse_source_name_with_template_args(&components)?;
                self.push_existing_component(&mut components, component)?;
                Ok(ParsedName {
                    components,
                    const_this: false,
                    arena_range: None,
                    template_scope: component.template_args,
                })
            }
            Some(first) if first.is_ascii_lowercase() => {
                let mut components = self.component_vec()?;
                let component = self.parse_operator_name_with_template_args(&components)?;
                self.push_existing_component(&mut components, component)?;
                Ok(ParsedName {
                    components,
                    const_this: false,
                    arena_range: None,
                    template_scope: component.template_args,
                })
            }
            found => Err(Failure::UnsupportedName {
                offset: self.position,
                found,
            }),
        }
    }

    fn parse_operator_name_with_template_args(
        &mut self,
        prefix: &[Component<'a>],
    ) -> Result<Component<'a>, Failure> {
        let offset = self.position;
        let first = self.byte();
        let second = self.peek(1);
        if (first, second) == (Some(b'c'), Some(b'v')) {
            return self.parse_conversion_operator(prefix);
        }
        let bytes = match (first, second) {
            (Some(b'r'), Some(b'm')) => b"operator%".as_slice(),
            (Some(b'p'), Some(b'l')) => b"operator+".as_slice(),
            (Some(b'l'), Some(b's')) => b"operator<<".as_slice(),
            (Some(b'n'), Some(b'g')) | (Some(b'm'), Some(b'i')) => b"operator-".as_slice(),
            (Some(b'l'), Some(b't')) => b"operator<".as_slice(),
            (Some(b'e'), Some(b'q')) => b"operator==".as_slice(),
            _ => {
                return Err(Failure::UnsupportedOperator {
                    offset,
                    first,
                    second,
                });
            }
        };
        self.position += 2;
        self.add_component()?;
        let mut component = Component {
            bytes,
            offset,
            template_args: None,
            destructor: false,
            conversion: None,
        };
        if self.byte() == Some(b'I') {
            let (candidate_start, candidate_end) = self.store_name_candidate(prefix, component)?;
            let candidate = self.push_type_node(TypeNode::Named {
                start: candidate_start,
                end: candidate_end,
            })?;
            self.add_substitution(candidate)?;
            component.template_args = Some(self.parse_template_args()?);
        }
        Ok(component)
    }

    fn parse_nested_name(&mut self) -> Result<ParsedName<'a>, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_nested_name_inner();
        self.depth = original_depth;
        result
    }

    fn parse_nested_name_inner(&mut self) -> Result<ParsedName<'a>, Failure> {
        self.position += 1;

        let const_this = if self.byte() == Some(b'K') {
            self.position += 1;
            true
        } else {
            false
        };
        let mut components = self.component_vec()?;
        let mut owner_name = None;
        let mut template_scope = None;
        let mut arena_start = None;
        let mut arena_end = self.type_name_components.len();
        let mut prefix_from_substitution = false;
        if self.byte() == Some(b'S')
            && matches!(self.peek(1), Some(b'_' | b'0'..=b'9' | b'A'..=b'Z'))
        {
            let substitution = self.parse_substitution()?;
            let (start, end) = match self.types.get(substitution).copied() {
                Some(TypeNode::Named { start, end }) => (start, end),
                _ => return Err(Failure::InvalidFunctionName),
            };
            let stored = self
                .type_name_components
                .get(start..end)
                .ok_or(Failure::InvalidFunctionName)?;
            let attempted = components.len().checked_add(stored.len()).ok_or(
                Failure::ComponentLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.components,
                },
            )?;
            if attempted > self.limits.components {
                return Err(Failure::ComponentLimitExceeded {
                    attempted,
                    limit: self.limits.components,
                });
            }
            components
                .try_reserve_exact(stored.len())
                .map_err(|_| Failure::AllocationFailed {
                    additional: stored.len(),
                })?;
            components.extend_from_slice(stored);
            arena_start = Some(start);
            arena_end = end;
            owner_name = components.last().map(|component| component.bytes);
            prefix_from_substitution = true;
        }
        if prefix_from_substitution && self.byte() == Some(b'I') {
            let arguments = self.parse_template_args()?;
            let component = components.last_mut().ok_or(Failure::InvalidFunctionName)?;
            component.template_args = Some(arguments);
            template_scope = Some(arguments);
            let range = self.store_name_components(&components)?;
            arena_start = Some(range.0);
            arena_end = range.1;
            if self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                let prefix = self.push_type_node(TypeNode::Named {
                    start: range.0,
                    end: range.1,
                })?;
                self.add_substitution(prefix)?;
            }
        }
        if self.byte() == Some(b'S') && self.peek(1) == Some(b't') {
            self.position += 2;
            let standard = self.standard_component();
            self.push_component(&mut components, standard)?;
            let range = self.store_name_components(&[standard])?;
            arena_start = Some(range.0);
            arena_end = range.1;
        }

        if components.is_empty() && self.byte() == Some(b'S') {
            let code = self.peek(1).ok_or(Failure::UnexpectedEnd {
                offset: self.position.saturating_add(1),
            })?;
            let constructor_context = matches!(self.peek(2), Some(b'C' | b'D'));
            let (simple, full, owner) = match code {
                b'a' => (
                    b"std::allocator".as_slice(),
                    b"std::allocator".as_slice(),
                    b"allocator".as_slice(),
                ),
                b'b' => (
                    b"std::basic_string".as_slice(),
                    b"std::basic_string".as_slice(),
                    b"basic_string".as_slice(),
                ),
                b's' => (
                    b"std::string".as_slice(),
                    b"std::basic_string<char, std::char_traits<char>, std::allocator<char> >"
                        .as_slice(),
                    b"basic_string".as_slice(),
                ),
                b'i' => (
                    b"std::istream".as_slice(),
                    b"std::basic_istream<char, std::char_traits<char> >".as_slice(),
                    b"basic_istream".as_slice(),
                ),
                b'o' => (
                    b"std::ostream".as_slice(),
                    b"std::basic_ostream<char, std::char_traits<char> >".as_slice(),
                    b"basic_ostream".as_slice(),
                ),
                b'd' => (
                    b"std::iostream".as_slice(),
                    b"std::basic_iostream<char, std::char_traits<char> >".as_slice(),
                    b"basic_iostream".as_slice(),
                ),
                _ => {
                    return Err(Failure::InvalidSubstitution {
                        offset: self.position,
                        found: Some(code),
                    })
                }
            };
            self.position += 2;
            let mut component = Component {
                bytes: if constructor_context { full } else { simple },
                offset: self.position.saturating_sub(2),
                template_args: None,
                destructor: false,
                conversion: None,
            };
            if matches!(code, b'a' | b'b') && self.byte() == Some(b'I') {
                component.template_args = Some(self.parse_template_args()?);
                template_scope = component.template_args;
            }
            self.push_component(&mut components, component)?;
            let range = self.store_name_components(&[component])?;
            arena_start = Some(range.0);
            arena_end = range.1;
            owner_name = Some(owner);
            if component.template_args.is_some()
                && self.byte().is_some_and(|byte| byte.is_ascii_digit())
            {
                let prefix = self.push_type_node(TypeNode::Named {
                    start: range.0,
                    end: range.1,
                })?;
                self.add_substitution(prefix)?;
            }
        }

        while self.byte().is_some_and(|byte| byte.is_ascii_digit())
            || (self.byte() == Some(b'L') && self.peek(1).is_some_and(|byte| byte.is_ascii_digit()))
        {
            let local_source = self.byte() == Some(b'L');
            if local_source {
                self.position += 1;
            }
            let arena_len_before_component = self.type_name_components.len();
            let component = self.parse_source_name_with_template_args(&components)?;
            if local_source {
                self.parse_discriminator()?;
            }
            if component.template_args.is_some() {
                template_scope = component.template_args;
            }
            owner_name = Some(component.bytes);
            self.push_existing_component(&mut components, component)?;
            if prefix_from_substitution {
                let range = self.store_name_components(&components)?;
                arena_start = Some(range.0);
                arena_end = range.1;
                prefix_from_substitution = false;
            } else if self.type_name_components.len() == arena_len_before_component {
                if arena_start.is_none() {
                    arena_start = Some(self.type_name_components.len());
                }
                arena_end = self.store_name_components(&[component])?.1;
            } else {
                let range = self.store_name_components(&components)?;
                arena_start = Some(range.0);
                arena_end = range.1;
            }
            if self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                let prefix = self.push_type_node(TypeNode::Named {
                    start: arena_start.ok_or(Failure::InvalidFunctionName)?,
                    end: arena_end,
                })?;
                self.add_substitution(prefix)?;
            }
        }

        if matches!(
            (self.byte(), self.peek(1)),
            (Some(b'e'), Some(b'q')) | (Some(b'm'), Some(b'i')) | (Some(b'c'), Some(b'v'))
        ) {
            let prefix_start = arena_start.ok_or(Failure::InvalidFunctionName)?;
            let prefix = self.push_type_node(TypeNode::Named {
                start: prefix_start,
                end: arena_end,
            })?;
            self.add_substitution(prefix)?;
            let component = self.parse_operator_name_with_template_args(&components)?;
            if component.template_args.is_some() {
                template_scope = component.template_args;
            }
            self.push_existing_component(&mut components, component)?;
            let range = self.store_name_components(&components)?;
            arena_start = Some(range.0);
            arena_end = range.1;
        }

        if matches!(self.byte(), Some(b'C' | b'D')) {
            let kind = self.byte().ok_or(Failure::UnexpectedEnd {
                offset: self.position,
            })?;
            let variant = self.peek(1).ok_or(Failure::UnexpectedEnd {
                offset: self.position.saturating_add(1),
            })?;
            let valid = match kind {
                b'C' => matches!(variant, b'1' | b'2' | b'3'),
                b'D' => matches!(variant, b'0' | b'1' | b'2'),
                _ => false,
            };
            if !valid {
                return Err(Failure::UnsupportedName {
                    offset: self.position,
                    found: Some(kind),
                });
            }
            let bytes = owner_name.ok_or(Failure::InvalidFunctionName)?;
            let component = Component {
                bytes,
                offset: self.position,
                template_args: None,
                destructor: kind == b'D',
                conversion: None,
            };
            self.position += 2;
            self.push_component(&mut components, component)?;
            let range = self.store_name_components(&components)?;
            arena_start = Some(range.0);
            arena_end = range.1;
        }

        if components.is_empty() {
            return Err(Failure::EmptyNestedName {
                offset: self.position,
            });
        }
        if self.byte() != Some(b'E') {
            return Err(Failure::MissingNestedTerminator {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;
        let arena_start = arena_start.ok_or(Failure::InvalidFunctionName)?;
        Ok(ParsedName {
            components,
            const_this,
            arena_range: Some((arena_start, arena_end)),
            template_scope,
        })
    }

    fn parse_source_name(&mut self) -> Result<Component<'a>, Failure> {
        let number_start = self.position;
        let mut length = 0usize;
        let mut saw_digit = false;
        while let Some(byte) = self.byte() {
            if !byte.is_ascii_digit() {
                break;
            }
            saw_digit = true;
            let digit = usize::from(byte - b'0');
            if length > ((i32::MAX as usize).saturating_sub(digit) / 10) {
                return Err(Failure::NumberOverflow {
                    start: number_start,
                    offset: self.position,
                });
            }
            length = length * 10 + digit;
            self.position += 1;
        }
        if !saw_digit || length == 0 {
            return Err(Failure::InvalidSourceName {
                offset: number_start,
                found: self.input.get(number_start).copied(),
            });
        }

        let offset = self.position;
        let remaining = self.input.len().saturating_sub(offset);
        let end = offset
            .checked_add(length)
            .ok_or(Failure::SourceNamePastEnd {
                offset,
                length,
                remaining,
            })?;
        let source_bytes = self
            .input
            .get(offset..end)
            .ok_or(Failure::SourceNamePastEnd {
                offset,
                length,
                remaining,
            })?;
        let bytes = if source_bytes.get(..8) == Some(b"_GLOBAL_")
            && matches!(source_bytes.get(8), Some(b'.' | b'_' | b'$'))
            && source_bytes.get(9) == Some(&b'N')
        {
            b"(anonymous namespace)".as_slice()
        } else {
            source_bytes
        };
        self.position = end;
        self.add_component()?;
        Ok(Component {
            bytes,
            offset,
            template_args: None,
            destructor: false,
            conversion: None,
        })
    }

    fn parse_discriminator(&mut self) -> Result<(), Failure> {
        if self.byte() != Some(b'_') {
            return Ok(());
        }
        self.position += 1;
        let double_underscore = self.byte() == Some(b'_');
        if double_underscore {
            self.position += 1;
        }

        let number_start = self.position;
        let mut number = 0usize;
        let mut saw_digit = false;
        while let Some(byte) = self.byte() {
            if !byte.is_ascii_digit() {
                break;
            }
            saw_digit = true;
            let digit = usize::from(byte - b'0');
            if number > ((i32::MAX as usize).saturating_sub(digit) / 10) {
                return Err(Failure::NumberOverflow {
                    start: number_start,
                    offset: self.position,
                });
            }
            number = number * 10 + digit;
            self.position += 1;
        }
        if !saw_digit {
            return Err(Failure::InvalidSourceName {
                offset: number_start,
                found: self.byte(),
            });
        }
        if double_underscore && number >= 10 {
            if self.byte() != Some(b'_') {
                return Err(Failure::UnsupportedName {
                    offset: self.position,
                    found: self.byte(),
                });
            }
            self.position += 1;
        }
        Ok(())
    }

    fn parse_conversion_operator(
        &mut self,
        prefix: &[Component<'a>],
    ) -> Result<Component<'a>, Failure> {
        let offset = self.position;
        self.position += 2;
        let conversion = if self.byte() == Some(b'T') {
            ConversionTarget::SelfTemplateParam(self.parse_template_parameter_index()?)
        } else {
            ConversionTarget::Type(self.parse_type()?)
        };
        self.add_component()?;
        let mut component = Component {
            bytes: b"operator ",
            offset,
            template_args: None,
            destructor: false,
            conversion: Some(conversion),
        };
        if self.byte() == Some(b'I') {
            let (candidate_start, candidate_end) = self.store_name_candidate(prefix, component)?;
            let candidate = self.push_type_node(TypeNode::Named {
                start: candidate_start,
                end: candidate_end,
            })?;
            self.add_substitution(candidate)?;
            component.template_args = Some(self.parse_template_args()?);
        } else if matches!(conversion, ConversionTarget::SelfTemplateParam(_)) {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        Ok(component)
    }

    fn parse_source_name_with_template_args(
        &mut self,
        prefix: &[Component<'a>],
    ) -> Result<Component<'a>, Failure> {
        let mut component = self.parse_source_name()?;
        if self.byte() != Some(b'I') {
            return Ok(component);
        }

        let (candidate_start, candidate_end) = self.store_name_candidate(prefix, component)?;
        let candidate = self.push_type_node(TypeNode::Named {
            start: candidate_start,
            end: candidate_end,
        })?;
        self.add_substitution(candidate)?;

        component.template_args = Some(self.parse_template_args()?);
        Ok(component)
    }

    fn parse_template_args(&mut self) -> Result<(usize, usize), Failure> {
        if self.byte() != Some(b'I') {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;
        let scope_count = self
            .in_progress_template_scopes
            .len()
            .checked_add(1)
            .ok_or(Failure::NestingLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.depth,
            })?;
        if scope_count > self.limits.depth {
            return Err(Failure::NestingLimitExceeded {
                attempted: scope_count,
                limit: self.limits.depth,
            });
        }
        self.in_progress_template_scopes
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        let original_depth = self.enter_depth()?;
        self.in_progress_template_scopes.push(Vec::new());
        let result = self.parse_template_args_inner();
        let _ = self.in_progress_template_scopes.pop();
        self.depth = original_depth;
        result
    }

    fn parse_template_args_inner(&mut self) -> Result<(usize, usize), Failure> {
        let start_offset = self.position.saturating_sub(1);
        if self.byte() == Some(b'E') {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        loop {
            let found = self.byte().ok_or(Failure::UnexpectedEnd {
                offset: self.position,
            })?;
            if found == b'E' {
                self.position += 1;
                break;
            }
            if matches!(found, b'I' | b'J') {
                return Err(Failure::InvalidTemplateArgument {
                    offset: self.position,
                    found: Some(found),
                });
            }
            let direct_count = self
                .in_progress_template_scopes
                .last()
                .ok_or(Failure::InvalidFunctionName)?
                .len()
                .checked_add(1)
                .ok_or(Failure::ComponentLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.components,
                })?;
            if direct_count > self.limits.components {
                return Err(Failure::ComponentLimitExceeded {
                    attempted: direct_count,
                    limit: self.limits.components,
                });
            }
            self.in_progress_template_scopes
                .last_mut()
                .ok_or(Failure::InvalidFunctionName)?
                .try_reserve(1)
                .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
            let argument = self.parse_template_argument()?;
            self.in_progress_template_scopes
                .last_mut()
                .ok_or(Failure::InvalidFunctionName)?
                .push(argument);
        }
        let direct_args = self
            .in_progress_template_scopes
            .last()
            .ok_or(Failure::InvalidFunctionName)?;
        if direct_args.is_empty() {
            return Err(Failure::InvalidTemplateArgument {
                offset: start_offset,
                found: Some(b'I'),
            });
        }
        let start = self.template_args.len();
        let end = start
            .checked_add(direct_args.len())
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if end > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: end,
                limit: self.limits.components,
            });
        }
        self.template_args
            .try_reserve(direct_args.len())
            .map_err(|_| Failure::AllocationFailed {
                additional: direct_args.len(),
            })?;
        self.template_args.extend_from_slice(direct_args);
        Ok((start, end))
    }

    fn parse_template_argument(&mut self) -> Result<TemplateArgId, Failure> {
        match self.byte() {
            Some(b'L') => Ok(TemplateArgId::Expr(self.parse_literal_expression()?)),
            Some(b'X') => Ok(TemplateArgId::Expr(self.parse_expression_wrapper()?)),
            Some(b'T') => {
                let argument = self.parse_template_parameter_argument()?;
                if let TemplateArgId::Type(ty) = argument {
                    self.add_substitution(ty)?;
                }
                Ok(argument)
            }
            _ => Ok(TemplateArgId::Type(self.parse_type()?)),
        }
    }

    fn parse_literal_expression(&mut self) -> Result<ExprId, Failure> {
        match self.peek(1) {
            Some(b'_' | b'Z') => self.parse_external_name_expression(),
            Some(b'f' | b'd' | b'e' | b'g') => self.parse_floating_literal(),
            _ => self.parse_integral_literal(),
        }
    }

    fn parse_floating_literal(&mut self) -> Result<ExprId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_floating_literal_inner();
        self.depth = original_depth;
        result
    }

    fn parse_floating_literal_inner(&mut self) -> Result<ExprId, Failure> {
        self.position += 1;
        let ty = self.parse_type()?;
        let valid_type = match self.types.get(ty) {
            Some(TypeNode::Builtin(name)) => {
                matches!(*name, "float" | "double" | "long double" | "__float128")
            }
            _ => false,
        };
        if !valid_type {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        let negative = if self.byte() == Some(b'n') {
            self.position += 1;
            true
        } else {
            false
        };
        let offset = self.position;
        while let Some(byte) = self.byte() {
            if byte == b'E' {
                break;
            }
            // Bundled d_expr_primary copies every non-NUL byte until uppercase
            // `E`; it deliberately does not interpret or validate the payload.
            if byte == 0 {
                return Err(Failure::InvalidTemplateArgument {
                    offset: self.position,
                    found: Some(byte),
                });
            }
            self.position += 1;
        }
        if self.position == offset || self.byte() != Some(b'E') {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        let digits = self
            .input
            .get(offset..self.position)
            .ok_or(Failure::InvalidFunctionName)?;
        self.position += 1;
        self.push_expression(ExprNode::FloatingLiteral {
            ty,
            digits,
            negative,
        })
    }

    fn parse_external_name_expression(&mut self) -> Result<ExprId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_external_name_expression_inner();
        self.depth = original_depth;
        result
    }

    fn parse_external_name_expression_inner(&mut self) -> Result<ExprId, Failure> {
        self.position += 1;
        match self.byte() {
            Some(b'_') => {
                self.position += 1;
                self.expect_prefix_byte(b'Z')?;
            }
            Some(b'Z') => self.position += 1,
            found => {
                return Err(Failure::InvalidTemplateArgument {
                    offset: self.position,
                    found,
                });
            }
        }
        if self.byte() == Some(b'Z') {
            return self.parse_external_local_name_inner();
        }
        let name = self.parse_name()?;
        self.active_template_scope = name.template_scope;
        let has_return_type = name.components.last().is_some_and(|component| {
            component.template_args.is_some() && component.conversion.is_none()
        });
        let function = if self.byte() == Some(b'E') {
            None
        } else {
            let function = self.parse_bare_function_type_until(has_return_type, Some(b'E'))?;
            if function.return_type.is_some() {
                return Err(Failure::UnsupportedName {
                    offset: self.position,
                    found: self.byte(),
                });
            }
            Some(function)
        };
        if self.byte() != Some(b'E') {
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;
        self.validate_component_template_args(&name.components, 0)?;
        self.validate_declarator_capabilities(DeclaratorInvocation::NamedFunction(
            function.as_ref(),
        ))?;
        let (components_start, components_end) = match name.arena_range {
            Some(range) => range,
            None => self.store_name_components(&name.components)?,
        };
        let arguments = match function {
            Some(function) => Some(self.store_function_arguments(&function.arguments)?),
            None => None,
        };
        self.push_expression(ExprNode::ExternalName {
            components_start,
            components_end,
            arguments,
            const_this: name.const_this,
        })
    }

    fn parse_external_local_name_inner(&mut self) -> Result<ExprId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_external_local_name_body(true);
        self.depth = original_depth;
        result
    }

    fn parse_external_local_name_body(
        &mut self,
        consume_outer_terminator: bool,
    ) -> Result<ExprId, Failure> {
        self.position += 1;
        if self.byte() == Some(b'Z') {
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: self.byte(),
            });
        }
        let scope_name = self.parse_name()?;
        self.active_template_scope = scope_name.template_scope;
        let has_return_type = scope_name.components.last().is_some_and(|component| {
            component.template_args.is_some() && component.conversion.is_none()
        });
        let mut scope_function =
            self.parse_bare_function_type_until(has_return_type, Some(b'E'))?;
        scope_function.return_type = None;
        if self.byte() != Some(b'E') {
            return Err(Failure::UnsupportedName {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;
        let entity_name = self.parse_local_entity_name()?;
        if consume_outer_terminator {
            if self.byte() != Some(b'E') {
                return Err(Failure::UnsupportedName {
                    offset: self.position,
                    found: self.byte(),
                });
            }
            self.position += 1;
        }

        self.validate_component_template_args(&scope_name.components, 0)?;
        self.validate_declarator_capabilities(DeclaratorInvocation::NamedFunction(Some(
            &scope_function,
        )))?;
        self.validate_component_template_args(&entity_name.components, 0)?;
        self.validate_declarator_capabilities(DeclaratorInvocation::NamedFunction(None))?;

        let (scope_components_start, scope_components_end) = match scope_name.arena_range {
            Some(range) => range,
            None => self.store_name_components(&scope_name.components)?,
        };
        let (scope_arguments_start, scope_arguments_end) =
            self.store_function_arguments(&scope_function.arguments)?;
        let (entity_components_start, entity_components_end) = match entity_name.arena_range {
            Some(range) => range,
            None => self.store_name_components(&entity_name.components)?,
        };
        self.push_expression(ExprNode::ExternalLocalName {
            scope_components_start,
            scope_components_end,
            scope_arguments_start,
            scope_arguments_end,
            scope_const_this: scope_name.const_this,
            entity_components_start,
            entity_components_end,
        })
    }

    fn store_function_arguments(
        &mut self,
        arguments: &[TypeId],
    ) -> Result<(usize, usize), Failure> {
        let start = self.function_args.len();
        let end = start
            .checked_add(arguments.len())
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if end > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: end,
                limit: self.limits.components,
            });
        }
        self.function_args
            .try_reserve(arguments.len())
            .map_err(|_| Failure::AllocationFailed {
                additional: arguments.len(),
            })?;
        self.function_args.extend_from_slice(arguments);
        Ok((start, end))
    }

    fn parse_expression_wrapper(&mut self) -> Result<ExprId, Failure> {
        let offset = self.position;
        if self.byte() != Some(b'X') {
            return Err(Failure::InvalidTemplateArgument {
                offset,
                found: self.byte(),
            });
        }
        self.position += 1;
        let expression = self.parse_expression()?;
        if self.byte() != Some(b'E') {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;
        Ok(expression)
    }

    fn parse_expression(&mut self) -> Result<ExprId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_expression_inner();
        self.depth = original_depth;
        result
    }

    fn parse_expression_inner(&mut self) -> Result<ExprId, Failure> {
        match (self.byte(), self.peek(1)) {
            (Some(b'L'), _) => self.parse_literal_expression(),
            (Some(b'T'), _) => {
                let offset = self.position;
                match self.parse_template_parameter_argument()? {
                    TemplateArgId::Expr(expression) => Ok(expression),
                    TemplateArgId::Type(_) => Err(Failure::InvalidTemplateArgument {
                        offset,
                        found: Some(b'T'),
                    }),
                }
            }
            (Some(b'c'), Some(b'v')) => {
                self.position += 2;
                let ty = self.parse_type()?;
                let operand = self.parse_expression()?;
                self.push_expression(ExprNode::Cast { ty, operand })
            }
            (Some(b'n'), Some(b'g')) => {
                self.position += 2;
                let operand = self.parse_expression()?;
                self.push_expression(ExprNode::Unary {
                    operator: UnaryOperator::Negate,
                    operand,
                })
            }
            (Some(b's'), Some(b'z')) => {
                self.position += 2;
                let operand = self.parse_expression()?;
                self.push_expression(ExprNode::Unary {
                    operator: UnaryOperator::SizeOf,
                    operand,
                })
            }
            (Some(b'p'), Some(b'l')) | (Some(b'g'), Some(b't')) => {
                let operator = if self.byte() == Some(b'p') {
                    BinaryOperator::Add
                } else {
                    BinaryOperator::Greater
                };
                self.position += 2;
                let left = self.parse_expression()?;
                let right = self.parse_expression()?;
                self.push_expression(ExprNode::Binary {
                    operator,
                    left,
                    right,
                })
            }
            _ => Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            }),
        }
    }

    fn push_expression(&mut self, expression: ExprNode<'a>) -> Result<ExprId, Failure> {
        self.add_component()?;
        let attempted =
            self.expressions
                .len()
                .checked_add(1)
                .ok_or(Failure::ComponentLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.components,
                })?;
        if attempted > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted,
                limit: self.limits.components,
            });
        }
        self.expressions
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        let id = self.expressions.len();
        self.expressions.push(expression);
        Ok(id)
    }

    fn parse_integral_literal(&mut self) -> Result<ExprId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_integral_literal_inner();
        self.depth = original_depth;
        result
    }

    fn parse_integral_literal_inner(&mut self) -> Result<ExprId, Failure> {
        let literal_offset = self.position;
        if self.byte() != Some(b'L') {
            return Err(Failure::InvalidTemplateArgument {
                offset: literal_offset,
                found: self.byte(),
            });
        }
        self.position += 1;
        let type_offset = self.position;
        let code = self.byte().ok_or(Failure::UnexpectedEnd {
            offset: self.position,
        })?;
        if !is_integral_literal_type(code) {
            return Err(Failure::UnsupportedType {
                offset: type_offset,
                found: code,
            });
        }
        let ty = self.parse_type()?;
        if self.position != type_offset.saturating_add(1) {
            return Err(Failure::UnsupportedType {
                offset: type_offset,
                found: code,
            });
        }

        let negative = self.byte() == Some(b'n');
        if negative {
            self.position += 1;
        }
        let digits_offset = self.position;
        while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        if self.position == digits_offset {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        if self.byte() != Some(b'E') {
            return Err(Failure::InvalidTemplateArgument {
                offset: self.position,
                found: self.byte(),
            });
        }
        let digits = self.input.get(digits_offset..self.position).ok_or(
            Failure::InvalidTemplateArgument {
                offset: digits_offset,
                found: self.input.get(digits_offset).copied(),
            },
        )?;
        self.position += 1;
        self.push_expression(ExprNode::IntegralLiteral {
            ty,
            digits,
            offset: digits_offset,
            negative,
        })
    }

    fn parse_bare_function_type(
        &mut self,
        has_return_type: bool,
    ) -> Result<ParsedFunctionType, Failure> {
        self.parse_bare_function_type_until(has_return_type, None)
    }

    fn parse_bare_function_type_until(
        &mut self,
        has_return_type: bool,
        terminator: Option<u8>,
    ) -> Result<ParsedFunctionType, Failure> {
        let return_type = if has_return_type {
            Some(self.parse_type()?)
        } else {
            None
        };
        let mut arguments = Vec::new();
        arguments
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;

        if self.byte() == Some(b'v') {
            let void_offset = self.position;
            self.position += 1;
            if self.byte().is_some() && self.byte() != terminator {
                return Err(Failure::VoidMixedWithArguments {
                    offset: void_offset,
                });
            }
            return Ok(ParsedFunctionType {
                return_type,
                arguments,
            });
        }

        while self.byte().is_some() && self.byte() != terminator {
            if self.byte() == Some(b'v') {
                return Err(Failure::VoidMixedWithArguments {
                    offset: self.position,
                });
            }
            arguments
                .try_reserve(1)
                .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
            arguments.push(self.parse_type()?);
        }
        if arguments.is_empty() {
            return Err(Failure::UnexpectedEnd {
                offset: self.position,
            });
        }
        Ok(ParsedFunctionType {
            return_type,
            arguments,
        })
    }

    fn parse_type(&mut self) -> Result<TypeId, Failure> {
        let mut modifiers = Vec::new();
        loop {
            let kind = match self.byte() {
                Some(b'P') => Modifier::Pointer,
                Some(b'R') => Modifier::Reference,
                Some(b'K') => Modifier::Const,
                Some(b'V') => Modifier::Volatile,
                Some(b'r') => Modifier::Restrict,
                _ => break,
            };
            let attempted = self
                .component_count
                .checked_add(modifiers.len())
                .and_then(|count| count.checked_add(1))
                .ok_or(Failure::ComponentLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.components,
                })?;
            if attempted > self.limits.components {
                return Err(Failure::ComponentLimitExceeded {
                    attempted,
                    limit: self.limits.components,
                });
            }
            modifiers
                .try_reserve(1)
                .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
            modifiers.push(kind);
            self.position += 1;
        }

        let mut segments = Vec::new();
        let mut index = 0;
        while index < modifiers.len() {
            segments
                .try_reserve(1)
                .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
            if modifiers[index].is_cv() {
                let start = index;
                while index < modifiers.len() && modifiers[index].is_cv() {
                    index += 1;
                }
                segments.push(ModifierSegment::Cv { start, end: index });
            } else {
                segments.push(ModifierSegment::Single(modifiers[index]));
                index += 1;
            }
        }

        let qualified_function =
            self.byte() == Some(b'F') && modifiers.last().is_some_and(|modifier| modifier.is_cv());
        let template_application_allowed = self.byte() == Some(b'T')
            || (self.byte() == Some(b'S')
                && self.peek(1).is_some_and(|byte| {
                    matches!(byte, b'a' | b'b' | b'_')
                        || byte.is_ascii_digit()
                        || byte.is_ascii_uppercase()
                }));
        let mut ty = self.parse_base_type(!qualified_function)?;
        if template_application_allowed && self.byte() == Some(b'I') {
            let template = ty;
            let (arguments_start, arguments_end) = self.parse_template_args()?;
            ty = self.add_type(TypeNode::AppliedTemplate {
                template,
                arguments_start,
                arguments_end,
            })?;
            self.add_substitution(ty)?;
        }
        for segment in segments.iter().rev() {
            match *segment {
                ModifierSegment::Single(kind) => {
                    ty = self.add_type(TypeNode::Modified { kind, inner: ty })?;
                    self.add_substitution(ty)?;
                }
                ModifierSegment::Cv { start, end } => {
                    for &kind in modifiers[start..end].iter().rev() {
                        ty = self.add_type(TypeNode::Modified { kind, inner: ty })?;
                    }
                    self.add_substitution(ty)?;
                }
            }
        }
        Ok(ty)
    }

    fn parse_base_type(&mut self, add_function_substitution: bool) -> Result<TypeId, Failure> {
        match self.byte() {
            Some(b'v') => {
                self.position += 1;
                self.add_type(TypeNode::Void)
            }
            Some(b'i') => {
                self.position += 1;
                self.add_type(TypeNode::Int)
            }
            Some(b'c') => {
                self.position += 1;
                self.add_type(TypeNode::Char)
            }
            Some(byte) if builtin_type_name(byte).is_some() => {
                self.position += 1;
                let text = builtin_type_name(byte).ok_or(Failure::UnsupportedType {
                    offset: self.position.saturating_sub(1),
                    found: byte,
                })?;
                self.add_type(TypeNode::Builtin(text))
            }
            Some(b'Z') => {
                let original_depth = self.enter_depth()?;
                let parsed = self.parse_external_local_name_body(false);
                self.depth = original_depth;
                let expression = parsed?;
                self.add_type(TypeNode::LocalName(expression))
            }
            Some(byte)
                if byte.is_ascii_digit()
                    || byte == b'N'
                    || (byte == b'S' && self.peek(1) == Some(b't')) =>
            {
                let name = self.parse_name()?;
                let (start, end) = match name.arena_range {
                    Some(range) => range,
                    None => self.store_name_components(&name.components)?,
                };
                let ty = self.push_type_node(TypeNode::Named { start, end })?;
                self.add_substitution(ty)?;
                Ok(ty)
            }
            Some(b'S') => self.parse_substitution(),
            Some(b'T') => self.parse_template_parameter(),
            Some(b'A') => self.parse_array_type(),
            Some(b'F') => self.parse_function_type(add_function_substitution),
            Some(b'M') => self.parse_member_pointer_type(),
            Some(b'U') => self.parse_vendor_qualified_type(),
            Some(found) => Err(Failure::UnsupportedType {
                offset: self.position,
                found,
            }),
            None => Err(Failure::UnexpectedEnd {
                offset: self.position,
            }),
        }
    }

    fn parse_function_type(&mut self, add_substitution: bool) -> Result<TypeId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_function_type_inner(add_substitution);
        self.depth = original_depth;
        result
    }

    fn parse_function_type_inner(&mut self, add_substitution: bool) -> Result<TypeId, Failure> {
        self.position += 1;
        let return_type = self.parse_type()?;
        let mut arguments = Vec::new();
        arguments
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;

        if self.byte() == Some(b'v') {
            let void_offset = self.position;
            self.position += 1;
            if self.byte() != Some(b'E') {
                return Err(Failure::VoidMixedWithArguments {
                    offset: void_offset,
                });
            }
        } else {
            while self.byte() != Some(b'E') {
                let found = self.byte().ok_or(Failure::UnexpectedEnd {
                    offset: self.position,
                })?;
                if found == b'v' {
                    return Err(Failure::VoidMixedWithArguments {
                        offset: self.position,
                    });
                }
                let attempted =
                    arguments
                        .len()
                        .checked_add(1)
                        .ok_or(Failure::ComponentLimitExceeded {
                            attempted: usize::MAX,
                            limit: self.limits.components,
                        })?;
                if attempted > self.limits.components {
                    return Err(Failure::ComponentLimitExceeded {
                        attempted,
                        limit: self.limits.components,
                    });
                }
                arguments
                    .try_reserve(1)
                    .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
                arguments.push(self.parse_type()?);
            }
            if arguments.is_empty() {
                return Err(Failure::UnexpectedEnd {
                    offset: self.position,
                });
            }
        }
        self.position += 1;

        let arguments_start = self.function_args.len();
        let arguments_end = arguments_start.checked_add(arguments.len()).ok_or(
            Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            },
        )?;
        if arguments_end > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: arguments_end,
                limit: self.limits.components,
            });
        }
        self.function_args
            .try_reserve(arguments.len())
            .map_err(|_| Failure::AllocationFailed {
                additional: arguments.len(),
            })?;
        self.function_args.extend_from_slice(&arguments);
        let ty = self.add_type(TypeNode::Function {
            return_type,
            arguments_start,
            arguments_end,
        })?;
        if add_substitution {
            self.add_substitution(ty)?;
        }
        Ok(ty)
    }

    fn parse_member_pointer_type(&mut self) -> Result<TypeId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_member_pointer_type_inner();
        self.depth = original_depth;
        result
    }

    fn parse_member_pointer_type_inner(&mut self) -> Result<TypeId, Failure> {
        self.position += 1;
        let class_offset = self.position;
        let class = self.parse_type()?;
        if !matches!(self.types.get(class), Some(TypeNode::Named { .. })) {
            let found = self
                .input
                .get(class_offset)
                .copied()
                .ok_or(Failure::UnexpectedEnd {
                    offset: class_offset,
                })?;
            return Err(Failure::UnsupportedType {
                offset: class_offset,
                found,
            });
        }
        let member = self.parse_type()?;
        let ty = self.add_type(TypeNode::MemberPointer { class, member })?;
        self.add_substitution(ty)?;
        Ok(ty)
    }

    fn parse_vendor_qualified_type(&mut self) -> Result<TypeId, Failure> {
        let original_depth = self.enter_depth()?;
        let result = self.parse_vendor_qualified_type_inner();
        self.depth = original_depth;
        result
    }

    fn parse_vendor_qualified_type_inner(&mut self) -> Result<TypeId, Failure> {
        self.position += 1;
        let mut component = self.parse_source_name()?;
        if self.byte() == Some(b'I') {
            component.template_args = Some(self.parse_template_args()?);
        }
        let (start, end) = self.store_name_components(&[component])?;
        if end != start.saturating_add(1) {
            return Err(Failure::InvalidFunctionName);
        }
        let inner = self.parse_type()?;
        let ty = self.add_type(TypeNode::VendorQualifier {
            qualifier: start,
            inner,
        })?;
        self.add_substitution(ty)?;
        Ok(ty)
    }

    fn parse_template_parameter(&mut self) -> Result<TypeId, Failure> {
        let offset = self.position;
        let argument = self.parse_template_parameter_argument()?;
        let ty = match argument {
            TemplateArgId::Type(ty) => ty,
            TemplateArgId::Expr(_) => {
                return Err(Failure::InvalidTemplateArgument {
                    offset,
                    found: Some(b'T'),
                });
            }
        };
        self.add_substitution(ty)?;
        Ok(ty)
    }

    fn parse_template_parameter_index(&mut self) -> Result<usize, Failure> {
        self.position += 1;
        if self.byte() == Some(b'_') {
            self.position += 1;
            return Ok(0);
        }
        let start = self.position;
        let mut value = 0usize;
        loop {
            let byte = self.byte().ok_or(Failure::UnexpectedEnd {
                offset: self.position,
            })?;
            if byte == b'_' {
                self.position += 1;
                break;
            }
            let digit = if byte.is_ascii_digit() {
                usize::from(byte - b'0')
            } else if byte.is_ascii_uppercase() {
                usize::from(byte - b'A') + 10
            } else {
                return Err(Failure::InvalidTemplateArgument {
                    offset: self.position,
                    found: Some(byte),
                });
            };
            value = value
                .checked_mul(36)
                .and_then(|current| current.checked_add(digit))
                .ok_or(Failure::TemplateParameterOverflow {
                    start,
                    offset: self.position,
                })?;
            self.position += 1;
        }
        value
            .checked_add(1)
            .ok_or(Failure::TemplateParameterOverflow {
                start,
                offset: self.position.saturating_sub(1),
            })
    }

    fn parse_template_parameter_argument(&mut self) -> Result<TemplateArgId, Failure> {
        let offset = self.position;
        let index = self.parse_template_parameter_index()?;
        let argument = if let Some((start, end)) = self.active_template_scope {
            let available = end.saturating_sub(start);
            let arena_index =
                start
                    .checked_add(index)
                    .ok_or(Failure::TemplateParameterOverflow {
                        start: offset,
                        offset: self.position,
                    })?;
            if arena_index >= end {
                return Err(Failure::TemplateParameterOutOfRange {
                    offset,
                    index,
                    available,
                });
            }
            self.template_args.get(arena_index).copied().ok_or(
                Failure::TemplateParameterOutOfRange {
                    offset,
                    index,
                    available,
                },
            )?
        } else if let Some(scope) = self
            .in_progress_template_scopes
            .iter()
            .rev()
            .find(|scope| !scope.is_empty())
        {
            let available = scope.len();
            scope
                .get(index)
                .copied()
                .ok_or(Failure::TemplateParameterOutOfRange {
                    offset,
                    index,
                    available,
                })?
        } else {
            return Err(Failure::TemplateParameterOutOfRange {
                offset,
                index,
                available: 0,
            });
        };
        Ok(argument)
    }

    fn parse_array_type(&mut self) -> Result<TypeId, Failure> {
        let original_depth = self.depth;
        let result = self.parse_array_type_inner();
        self.depth = original_depth;
        result
    }

    fn parse_array_type_inner(&mut self) -> Result<TypeId, Failure> {
        let mut dimensions = Vec::new();
        while self.byte() == Some(b'A') {
            self.enter_depth()?;
            let attempted =
                dimensions
                    .len()
                    .checked_add(1)
                    .ok_or(Failure::ComponentLimitExceeded {
                        attempted: usize::MAX,
                        limit: self.limits.components,
                    })?;
            if attempted > self.limits.components {
                return Err(Failure::ComponentLimitExceeded {
                    attempted,
                    limit: self.limits.components,
                });
            }
            dimensions
                .try_reserve(1)
                .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
            dimensions.push(self.parse_array_dimension()?);
        }

        let mut ty = self.parse_type()?;
        for dimension in dimensions.into_iter().rev() {
            ty = self.add_type(TypeNode::Array {
                dimension,
                element: ty,
            })?;
            self.add_substitution(ty)?;
        }
        Ok(ty)
    }

    fn parse_array_dimension(&mut self) -> Result<ArrayDimension, Failure> {
        self.position += 1;
        if self.byte() == Some(b'_') {
            self.position += 1;
            return Ok(ArrayDimension::Absent);
        }
        let number_start = self.position;
        let mut dimension = 0usize;
        let mut saw_digit = false;
        while let Some(byte) = self.byte() {
            if !byte.is_ascii_digit() {
                break;
            }
            saw_digit = true;
            let digit = usize::from(byte - b'0');
            if dimension > ((i32::MAX as usize).saturating_sub(digit) / 10) {
                return Err(Failure::NumberOverflow {
                    start: number_start,
                    offset: self.position,
                });
            }
            dimension = dimension * 10 + digit;
            self.position += 1;
        }
        if saw_digit {
            if self.byte() != Some(b'_') {
                return Err(Failure::InvalidArrayDimension {
                    offset: self.position,
                    found: self.byte(),
                });
            }
            self.position += 1;
            return Ok(ArrayDimension::Number(dimension));
        }

        let expression = self.parse_expression().map_err(|failure| match failure {
            Failure::InvalidTemplateArgument { offset, found } => {
                Failure::InvalidArrayDimension { offset, found }
            }
            other => other,
        })?;
        if self.byte() != Some(b'_') {
            return Err(Failure::InvalidArrayDimension {
                offset: self.position,
                found: self.byte(),
            });
        }
        self.position += 1;
        Ok(ArrayDimension::Expression(expression))
    }

    fn parse_substitution(&mut self) -> Result<TypeId, Failure> {
        let substitution_offset = self.position;
        self.position += 1;
        match self.byte() {
            Some(b'a') => {
                self.position += 1;
                self.add_type(TypeNode::Standard("std::allocator"))
            }
            Some(b'b') => {
                self.position += 1;
                self.add_type(TypeNode::Standard("std::basic_string"))
            }
            Some(b'i') => {
                self.position += 1;
                self.add_type(TypeNode::Standard("std::istream"))
            }
            Some(b'd') => {
                self.position += 1;
                self.add_type(TypeNode::Standard("std::iostream"))
            }
            Some(b's') => {
                self.position += 1;
                self.add_type(TypeNode::Standard("std::string"))
            }
            Some(b'o') => {
                self.position += 1;
                self.add_type(TypeNode::Standard("std::ostream"))
            }
            Some(b'_') => {
                self.position += 1;
                self.substitution_at(substitution_offset, 0)
            }
            Some(byte) if byte.is_ascii_digit() || byte.is_ascii_uppercase() => {
                let number_start = self.position;
                let mut value = 0usize;
                loop {
                    let byte = self.byte().ok_or(Failure::UnexpectedEnd {
                        offset: self.position,
                    })?;
                    if byte == b'_' {
                        self.position += 1;
                        break;
                    }
                    let digit = if byte.is_ascii_digit() {
                        usize::from(byte - b'0')
                    } else if byte.is_ascii_uppercase() {
                        usize::from(byte - b'A') + 10
                    } else {
                        return Err(Failure::InvalidSubstitution {
                            offset: self.position,
                            found: Some(byte),
                        });
                    };
                    value = value
                        .checked_mul(36)
                        .and_then(|current| current.checked_add(digit))
                        .ok_or(Failure::SubstitutionOverflow {
                            start: number_start,
                            offset: self.position,
                        })?;
                    self.position += 1;
                }
                let index = value.checked_add(1).ok_or(Failure::SubstitutionOverflow {
                    start: number_start,
                    offset: self.position.saturating_sub(1),
                })?;
                self.substitution_at(substitution_offset, index)
            }
            found => Err(Failure::InvalidSubstitution {
                offset: self.position,
                found,
            }),
        }
    }

    fn substitution_at(&self, offset: usize, index: usize) -> Result<TypeId, Failure> {
        self.substitutions
            .get(index)
            .copied()
            .ok_or(Failure::SubstitutionOutOfRange {
                offset,
                index,
                available: self.substitutions.len(),
            })
    }

    fn add_type(&mut self, ty: TypeNode) -> Result<TypeId, Failure> {
        self.add_component()?;
        self.push_type_node(ty)
    }

    fn push_type_node(&mut self, ty: TypeNode) -> Result<TypeId, Failure> {
        if self.types.len() >= self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: self.types.len().saturating_add(1),
                limit: self.limits.components,
            });
        }
        self.types
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        let id = self.types.len();
        self.types.push(ty);
        Ok(id)
    }

    fn store_name_components(
        &mut self,
        components: &[Component<'a>],
    ) -> Result<(usize, usize), Failure> {
        let start = self.type_name_components.len();
        let end = start
            .checked_add(components.len())
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if end > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: end,
                limit: self.limits.components,
            });
        }
        self.type_name_components
            .try_reserve(components.len())
            .map_err(|_| Failure::AllocationFailed {
                additional: components.len(),
            })?;
        self.type_name_components.extend_from_slice(components);
        Ok((start, end))
    }

    fn store_name_candidate(
        &mut self,
        prefix: &[Component<'a>],
        component: Component<'a>,
    ) -> Result<(usize, usize), Failure> {
        let additional = prefix
            .len()
            .checked_add(1)
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        let start = self.type_name_components.len();
        let end = start
            .checked_add(additional)
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if end > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: end,
                limit: self.limits.components,
            });
        }
        self.type_name_components
            .try_reserve(additional)
            .map_err(|_| Failure::AllocationFailed { additional })?;
        self.type_name_components.extend_from_slice(prefix);
        self.type_name_components.push(component);
        Ok((start, end))
    }

    fn add_substitution(&mut self, ty: TypeId) -> Result<(), Failure> {
        let attempted =
            self.substitutions
                .len()
                .checked_add(1)
                .ok_or(Failure::BackreferenceLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.backreferences,
                })?;
        if attempted > self.limits.backreferences {
            return Err(Failure::BackreferenceLimitExceeded {
                attempted,
                limit: self.limits.backreferences,
            });
        }
        self.substitutions
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        self.substitutions.push(ty);
        Ok(())
    }

    fn validate_declarator_capabilities(
        &self,
        invocation: DeclaratorInvocation<'_>,
    ) -> Result<(), Failure> {
        let mut work = Vec::new();
        let mut scheduled = 0usize;
        match invocation {
            DeclaratorInvocation::NamedFunction(function) => {
                if let Some(function) = function {
                    self.push_declarator_work(
                        &mut work,
                        &mut scheduled,
                        DeclaratorWork::Types {
                            types: &function.arguments,
                            depth: 0,
                        },
                    )?;
                }
                if let Some(return_type) = function.and_then(|value| value.return_type) {
                    self.push_declarator_work(
                        &mut work,
                        &mut scheduled,
                        DeclaratorWork::Type {
                            type_id: return_type,
                            depth: 0,
                        },
                    )?;
                }
            }
            DeclaratorInvocation::StandaloneType(type_id) => self.push_declarator_work(
                &mut work,
                &mut scheduled,
                DeclaratorWork::Type { type_id, depth: 0 },
            )?,
        }
        self.run_declarator_work(work, scheduled)
    }

    fn run_declarator_work<'work>(
        &self,
        mut work: Vec<DeclaratorWork<'work, 'a>>,
        mut scheduled: usize,
    ) -> Result<(), Failure> {
        while let Some(item) = work.pop() {
            match item {
                DeclaratorWork::Type { type_id, depth } => {
                    if depth > self.limits.depth {
                        return Err(Failure::NestingLimitExceeded {
                            attempted: depth,
                            limit: self.limits.depth,
                        });
                    }
                    let child_depth =
                        depth.checked_add(1).ok_or(Failure::NestingLimitExceeded {
                            attempted: usize::MAX,
                            limit: self.limits.depth,
                        })?;
                    let base = self.declarator_base(type_id)?;
                    match *self.types.get(base).ok_or(Failure::InvalidFunctionName)? {
                        TypeNode::VendorQualifier { qualifier, inner } => {
                            let component = *self
                                .type_name_components
                                .get(qualifier)
                                .ok_or(Failure::InvalidFunctionName)?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type {
                                    type_id: inner,
                                    depth: child_depth,
                                },
                            )?;
                            if let Some((start, end)) = component.template_args {
                                self.push_declarator_work(
                                    &mut work,
                                    &mut scheduled,
                                    DeclaratorWork::TemplateArguments {
                                        start,
                                        end,
                                        depth: child_depth,
                                    },
                                )?;
                            }
                        }
                        TypeNode::Array { element, .. } => {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type {
                                    type_id: element,
                                    depth: child_depth,
                                },
                            )?;
                        }
                        TypeNode::Function {
                            return_type,
                            arguments_start,
                            arguments_end,
                        } => {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::FunctionArguments {
                                    start: arguments_start,
                                    end: arguments_end,
                                    depth: child_depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type {
                                    type_id: return_type,
                                    depth: child_depth,
                                },
                            )?;
                        }
                        TypeNode::MemberPointer { class, member } => {
                            if class == type_id || member == type_id {
                                return Err(Failure::InvalidFunctionName);
                            }
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type {
                                    type_id: member,
                                    depth: child_depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type {
                                    type_id: class,
                                    depth: child_depth,
                                },
                            )?;
                        }
                        TypeNode::AppliedTemplate {
                            template,
                            arguments_start,
                            arguments_end,
                        } => {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::TemplateArguments {
                                    start: arguments_start,
                                    end: arguments_end,
                                    depth: child_depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type {
                                    type_id: template,
                                    depth: child_depth,
                                },
                            )?;
                        }
                        TypeNode::Named { start, end } => self.push_declarator_work(
                            &mut work,
                            &mut scheduled,
                            DeclaratorWork::StoredComponents {
                                start,
                                end,
                                depth: child_depth,
                            },
                        )?,
                        TypeNode::LocalName(expr_id) => self.push_declarator_work(
                            &mut work,
                            &mut scheduled,
                            DeclaratorWork::Expression {
                                expr_id,
                                depth: child_depth,
                            },
                        )?,
                        TypeNode::Void
                        | TypeNode::Int
                        | TypeNode::Char
                        | TypeNode::Builtin(_)
                        | TypeNode::Standard(_) => {}
                        TypeNode::Modified { .. } => return Err(Failure::InvalidFunctionName),
                    }
                }
                DeclaratorWork::Components { components, depth } => {
                    for component in components.iter().rev() {
                        if let Some(type_id) = self.resolve_conversion_type(*component)? {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type { type_id, depth },
                            )?;
                        }
                        if let Some((start, end)) = component.template_args {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::TemplateArguments { start, end, depth },
                            )?;
                        }
                    }
                }
                DeclaratorWork::StoredComponents { start, end, depth } => {
                    let components = self
                        .type_name_components
                        .get(start..end)
                        .ok_or(Failure::InvalidFunctionName)?;
                    for component in components.iter().rev() {
                        if let Some(type_id) = self.resolve_conversion_type(*component)? {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type { type_id, depth },
                            )?;
                        }
                        if let Some((start, end)) = component.template_args {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::TemplateArguments { start, end, depth },
                            )?;
                        }
                    }
                }
                DeclaratorWork::FunctionArguments { start, end, depth } => {
                    let types = self
                        .function_args
                        .get(start..end)
                        .ok_or(Failure::InvalidFunctionName)?;
                    self.push_declarator_types(&mut work, &mut scheduled, types, depth)?;
                }
                DeclaratorWork::TemplateArguments { start, end, depth } => {
                    let arguments = self
                        .template_args
                        .get(start..end)
                        .ok_or(Failure::InvalidFunctionName)?;
                    for argument in arguments.iter().rev() {
                        match *argument {
                            TemplateArgId::Type(type_id) => self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type { type_id, depth },
                            )?,
                            TemplateArgId::Expr(expr_id) => self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Expression { expr_id, depth },
                            )?,
                        }
                    }
                }
                DeclaratorWork::Expression { expr_id, depth } => {
                    match *self
                        .expressions
                        .get(expr_id)
                        .ok_or(Failure::InvalidFunctionName)?
                    {
                        ExprNode::IntegralLiteral { ty, .. }
                        | ExprNode::FloatingLiteral { ty, .. } => self.push_declarator_work(
                            &mut work,
                            &mut scheduled,
                            DeclaratorWork::Type { type_id: ty, depth },
                        )?,
                        ExprNode::Cast { ty, operand } => {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Expression {
                                    expr_id: operand,
                                    depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Type { type_id: ty, depth },
                            )?;
                        }
                        ExprNode::Binary { left, right, .. } => {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Expression {
                                    expr_id: right,
                                    depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::Expression {
                                    expr_id: left,
                                    depth,
                                },
                            )?;
                        }
                        ExprNode::Unary { operand, .. } => self.push_declarator_work(
                            &mut work,
                            &mut scheduled,
                            DeclaratorWork::Expression {
                                expr_id: operand,
                                depth,
                            },
                        )?,
                        ExprNode::ExternalName {
                            components_start,
                            components_end,
                            arguments,
                            ..
                        } => {
                            if let Some((start, end)) = arguments {
                                self.push_declarator_work(
                                    &mut work,
                                    &mut scheduled,
                                    DeclaratorWork::FunctionArguments { start, end, depth },
                                )?;
                            }
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::StoredComponents {
                                    start: components_start,
                                    end: components_end,
                                    depth,
                                },
                            )?;
                        }
                        ExprNode::ExternalLocalName {
                            scope_components_start,
                            scope_components_end,
                            scope_arguments_start,
                            scope_arguments_end,
                            entity_components_start,
                            entity_components_end,
                            ..
                        } => {
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::StoredComponents {
                                    start: entity_components_start,
                                    end: entity_components_end,
                                    depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::FunctionArguments {
                                    start: scope_arguments_start,
                                    end: scope_arguments_end,
                                    depth,
                                },
                            )?;
                            self.push_declarator_work(
                                &mut work,
                                &mut scheduled,
                                DeclaratorWork::StoredComponents {
                                    start: scope_components_start,
                                    end: scope_components_end,
                                    depth,
                                },
                            )?;
                        }
                    }
                }
                DeclaratorWork::Types { types, depth } => {
                    self.push_declarator_types(&mut work, &mut scheduled, types, depth)?;
                }
            }
        }
        Ok(())
    }

    fn validate_component_template_args(
        &self,
        components: &[Component<'a>],
        depth: usize,
    ) -> Result<(), Failure> {
        let mut work = Vec::new();
        let mut scheduled = 0usize;
        self.push_declarator_work(
            &mut work,
            &mut scheduled,
            DeclaratorWork::Components { components, depth },
        )?;
        self.run_declarator_work(work, scheduled)
    }

    fn push_declarator_types<'work>(
        &self,
        work: &mut Vec<DeclaratorWork<'work, 'a>>,
        scheduled: &mut usize,
        types: &[TypeId],
        depth: usize,
    ) -> Result<(), Failure> {
        for &type_id in types.iter().rev() {
            self.push_declarator_work(work, scheduled, DeclaratorWork::Type { type_id, depth })?;
        }
        Ok(())
    }

    /// Work-stack invariant: every scheduled validation step is heap-resident, both the
    /// live stack and cumulative pushes stay within the effective component limit, and
    /// capacity is reserved fallibly before the stack is mutated.
    fn push_declarator_work<'work>(
        &self,
        work: &mut Vec<DeclaratorWork<'work, 'a>>,
        scheduled: &mut usize,
        item: DeclaratorWork<'work, 'a>,
    ) -> Result<(), Failure> {
        let limit = self.limits.components.min(MAX_COMPONENTS);
        let attempted = scheduled
            .checked_add(1)
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit,
            })?;
        if attempted > limit {
            return Err(Failure::ComponentLimitExceeded { attempted, limit });
        }
        let stack_size = work
            .len()
            .checked_add(1)
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit,
            })?;
        if stack_size > limit {
            return Err(Failure::ComponentLimitExceeded {
                attempted: stack_size,
                limit,
            });
        }
        work.try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        work.push(item);
        *scheduled = attempted;
        Ok(())
    }

    fn type_requires_standalone_injection(&self, type_id: TypeId) -> Result<bool, Failure> {
        let base = self.declarator_base(type_id)?;
        match *self.types.get(base).ok_or(Failure::InvalidFunctionName)? {
            TypeNode::Function { return_type, .. } => {
                self.type_requires_name_injection(return_type)
            }
            TypeNode::Array { element, .. } => {
                let element_base = self.declarator_base(element)?;
                Ok(
                    !matches!(self.types.get(element_base), Some(TypeNode::Array { .. }))
                        && self.type_requires_name_injection(element)?,
                )
            }
            TypeNode::MemberPointer { member, .. } => {
                let member_base = self.declarator_base(member)?;
                match self.types.get(member_base).copied() {
                    Some(TypeNode::Function { return_type, .. }) => {
                        self.type_requires_name_injection(return_type)
                    }
                    Some(_) => self.type_requires_name_injection(member),
                    None => Err(Failure::InvalidFunctionName),
                }
            }
            _ => Ok(false),
        }
    }

    fn type_requires_name_injection(&self, type_id: TypeId) -> Result<bool, Failure> {
        let mut current = type_id;
        let mut remaining = self
            .types
            .len()
            .checked_add(1)
            .ok_or(Failure::InvalidFunctionName)?;
        loop {
            remaining = remaining
                .checked_sub(1)
                .ok_or(Failure::InvalidFunctionName)?;
            let base = self.declarator_base(current)?;
            match *self.types.get(base).ok_or(Failure::InvalidFunctionName)? {
                TypeNode::Function { .. } | TypeNode::Array { .. } => return Ok(true),
                TypeNode::MemberPointer { member, .. } => current = member,
                TypeNode::VendorQualifier { inner, .. } => current = inner,
                TypeNode::AppliedTemplate { template, .. } => current = template,
                TypeNode::Void
                | TypeNode::Int
                | TypeNode::Char
                | TypeNode::Builtin(_)
                | TypeNode::Named { .. }
                | TypeNode::Standard(_)
                | TypeNode::LocalName(_) => return Ok(false),
                TypeNode::Modified { .. } => return Err(Failure::InvalidFunctionName),
            }
        }
    }

    fn declarator_base(&self, mut ty: TypeId) -> Result<TypeId, Failure> {
        let mut remaining = self
            .types
            .len()
            .checked_add(1)
            .ok_or(Failure::InvalidFunctionName)?;
        loop {
            remaining = remaining
                .checked_sub(1)
                .ok_or(Failure::InvalidFunctionName)?;
            match self.types.get(ty).ok_or(Failure::InvalidFunctionName)? {
                TypeNode::Modified { inner, .. } => ty = *inner,
                _ => return Ok(ty),
            }
        }
    }

    fn render_local_name(
        &mut self,
        prefix: &'static str,
        parts: &[LocalNamePart<'a>],
    ) -> Result<FunctionName, Failure> {
        let mut output_len = prefix.len();
        for (part_index, part) in parts.iter().enumerate() {
            if part_index != 0 {
                output_len = checked_output_add(output_len, 2, self.limits.output)?;
            }
            output_len = checked_output_add(
                output_len,
                self.components_len(&part.name.components)?,
                self.limits.output,
            )?;
            if let Some(function) = &part.function {
                output_len = checked_output_add(output_len, 2, self.limits.output)?;
                for (argument_index, argument) in function.arguments.iter().enumerate() {
                    if argument_index != 0 {
                        output_len = checked_output_add(output_len, 2, self.limits.output)?;
                    }
                    output_len = checked_output_add(
                        output_len,
                        self.type_len(*argument)?,
                        self.limits.output,
                    )?;
                }
                if part.name.const_this {
                    output_len = checked_output_add(output_len, 6, self.limits.output)?;
                }
            }
        }
        let budget_used = self.budget.preflight(output_len)?;
        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| Failure::AllocationFailed {
                additional: output_len,
            })?;
        self.budget.commit(budget_used);
        output.push_str(prefix);
        for (part_index, part) in parts.iter().enumerate() {
            if part_index != 0 {
                output.push_str("::");
            }
            self.push_components(&mut output, &part.name.components)?;
            if let Some(function) = &part.function {
                output.push('(');
                for (argument_index, argument) in function.arguments.iter().enumerate() {
                    if argument_index != 0 {
                        output.push_str(", ");
                    }
                    self.push_type_text(&mut output, *argument)?;
                }
                output.push(')');
                if part.name.const_this {
                    output.push_str(" const");
                }
            }
        }
        FunctionName::new(output, 0).map_err(|_| Failure::InvalidFunctionName)
    }

    fn prepend_declarator_plan(
        &self,
        hole: &mut Vec<TypeRenderPart<'a>>,
        prefix: Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        let attempted =
            prefix
                .len()
                .checked_add(hole.len())
                .ok_or(Failure::ComponentLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.components,
                })?;
        if attempted > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted,
                limit: self.limits.components,
            });
        }
        let mut combined = Vec::new();
        combined
            .try_reserve_exact(attempted)
            .map_err(|_| Failure::AllocationFailed {
                additional: attempted,
            })?;
        combined.extend(prefix);
        combined.append(hole);
        *hole = combined;
        Ok(())
    }

    fn build_injected_type_plan(
        &self,
        mut current: TypeId,
        mut hole: Vec<TypeRenderPart<'a>>,
    ) -> Result<Vec<TypeRenderPart<'a>>, Failure> {
        let mut pointer_like = false;
        let mut member_pointer_hole = false;
        let mut remaining = self
            .types
            .len()
            .checked_add(1)
            .ok_or(Failure::InvalidFunctionName)?;
        loop {
            remaining = remaining
                .checked_sub(1)
                .ok_or(Failure::InvalidFunctionName)?;
            let (base, modifiers) = self.normalized_type_parts(current)?;
            let node = *self.types.get(base).ok_or(Failure::InvalidFunctionName)?;
            let mut function_cv_start = modifiers.len();
            if matches!(node, TypeNode::Function { .. }) {
                while function_cv_start > 0
                    && modifiers
                        .get(function_cv_start - 1)
                        .is_some_and(|modifier| modifier.is_cv())
                {
                    function_cv_start -= 1;
                }
            }
            let declarator_modifiers = modifiers
                .get(..function_cv_start)
                .ok_or(Failure::InvalidFunctionName)?;
            if !declarator_modifiers.is_empty() {
                let mut prefix = Vec::new();
                self.push_modifier_plan(&mut prefix, declarator_modifiers)?;
                if member_pointer_hole
                    && declarator_modifiers
                        .iter()
                        .any(|modifier| matches!(modifier, Modifier::Pointer | Modifier::Reference))
                {
                    self.push_plan_text(&mut prefix, " ")?;
                    member_pointer_hole = false;
                } else if !hole.is_empty()
                    && !matches!(
                        hole.first(),
                        Some(TypeRenderPart::Text(text)) if text.starts_with(' ')
                    )
                    && declarator_modifiers.iter().any(|modifier| modifier.is_cv())
                {
                    self.push_plan_text(&mut prefix, " ")?;
                }
                self.prepend_declarator_plan(&mut hole, prefix)?;
                pointer_like |= declarator_modifiers
                    .iter()
                    .any(|modifier| matches!(modifier, Modifier::Pointer | Modifier::Reference));
            }
            match node {
                TypeNode::Array { dimension, element } => {
                    if pointer_like && !hole.is_empty() {
                        {
                            let mut prefix = Vec::new();
                            self.push_plan_text(&mut prefix, " (")?;
                            self.prepend_declarator_plan(&mut hole, prefix)?;
                        }
                        self.push_plan_text(&mut hole, ")")?;
                    }
                    self.push_plan_text(&mut hole, " [")?;
                    match dimension {
                        ArrayDimension::Absent => {}
                        ArrayDimension::Number(value) => {
                            self.push_plan_part(&mut hole, TypeRenderPart::Decimal(value))?
                        }
                        ArrayDimension::Expression(expr) => {
                            self.build_expr_plan(expr, &mut hole)?
                        }
                    }
                    self.push_plan_text(&mut hole, "]")?;
                    pointer_like = false;
                    current = element;
                }
                TypeNode::Function {
                    return_type,
                    arguments_start,
                    arguments_end,
                } => {
                    if pointer_like && !hole.is_empty() {
                        {
                            let mut prefix = Vec::new();
                            self.push_plan_text(&mut prefix, "(")?;
                            self.prepend_declarator_plan(&mut hole, prefix)?;
                        }
                        self.push_plan_text(&mut hole, ")")?;
                    }
                    self.push_plan_text(&mut hole, "(")?;
                    let arguments = self
                        .function_args
                        .get(arguments_start..arguments_end)
                        .ok_or(Failure::InvalidFunctionName)?;
                    for (index, argument) in arguments.iter().enumerate() {
                        if index != 0 {
                            self.push_plan_text(&mut hole, ", ")?;
                        }
                        self.build_type_plan(*argument, &mut hole)?;
                    }
                    self.push_plan_text(&mut hole, ")")?;
                    self.push_modifier_plan(
                        &mut hole,
                        modifiers
                            .get(function_cv_start..)
                            .ok_or(Failure::InvalidFunctionName)?,
                    )?;
                    pointer_like = false;
                    current = return_type;
                }
                TypeNode::MemberPointer { class, member } => {
                    let mut prefix = Vec::new();
                    self.build_class_plan(class, &mut prefix)?;
                    self.push_plan_text(&mut prefix, "::*")?;
                    self.prepend_declarator_plan(&mut hole, prefix)?;
                    member_pointer_hole = true;
                    pointer_like = true;
                    current = member;
                }
                TypeNode::Modified { .. } => return Err(Failure::InvalidFunctionName),
                _ => {
                    let mut plan = Vec::new();
                    self.build_type_plan_parts(base, &[], &mut plan)?;
                    if !hole.is_empty()
                        && !matches!(hole.first(), Some(TypeRenderPart::Text(text)) if text.starts_with(' '))
                    {
                        self.push_plan_text(&mut plan, " ")?;
                    }
                    for part in hole {
                        self.push_plan_part(&mut plan, part)?;
                    }
                    return Ok(plan);
                }
            }
        }
    }

    fn render_injected_name(
        &mut self,
        prefix: &'static str,
        name: &ParsedName<'a>,
        function: &ParsedFunctionType,
        return_type: TypeId,
    ) -> Result<FunctionName, Failure> {
        let mut hole = Vec::new();
        self.build_component_slice_plan(&name.components, &mut hole)?;
        self.push_plan_text(&mut hole, "(")?;
        for (index, argument) in function.arguments.iter().enumerate() {
            if index != 0 {
                self.push_plan_text(&mut hole, ", ")?;
            }
            self.build_type_plan(*argument, &mut hole)?;
        }
        self.push_plan_text(&mut hole, ")")?;
        if name.const_this {
            self.push_plan_text(&mut hole, " const")?;
        }
        let plan = self.build_injected_type_plan(return_type, hole)?;
        let plan_len = self.render_plan_slice_len(&plan)?;
        let output_len = checked_output_add(prefix.len(), plan_len, self.limits.output)?;
        let budget_used = self.budget.preflight(output_len)?;
        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| Failure::AllocationFailed {
                additional: output_len,
            })?;
        self.budget.commit(budget_used);
        output.push_str(prefix);
        self.push_render_plan(&mut output, plan)?;
        FunctionName::new(output, 0).map_err(|_| Failure::InvalidFunctionName)
    }

    fn render(
        &mut self,
        prefix: &'static str,
        name: ParsedName<'a>,
        function: Option<&ParsedFunctionType>,
    ) -> Result<FunctionName, Failure> {
        if let Some((function, return_type)) = function.and_then(|function| {
            function
                .return_type
                .map(|return_type| (function, return_type))
        }) {
            if self.type_requires_name_injection(return_type)? {
                return self.render_injected_name(prefix, &name, function, return_type);
            }
        }
        let mut output_len = prefix.len();
        if let Some(return_type) = function.and_then(|value| value.return_type) {
            output_len =
                checked_output_add(output_len, self.type_len(return_type)?, self.limits.output)?;
            output_len = checked_output_add(output_len, 1, self.limits.output)?;
        }
        output_len = checked_output_add(
            output_len,
            self.components_len(&name.components)?,
            self.limits.output,
        )?;
        if let Some(function) = function {
            output_len = checked_output_add(output_len, 2, self.limits.output)?;
            for (index, argument) in function.arguments.iter().enumerate() {
                if index != 0 {
                    output_len = checked_output_add(output_len, 2, self.limits.output)?;
                }
                output_len =
                    checked_output_add(output_len, self.type_len(*argument)?, self.limits.output)?;
            }
            if name.const_this {
                output_len = checked_output_add(output_len, 6, self.limits.output)?;
            }
        }
        let budget_used = self.budget.preflight(output_len)?;

        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| Failure::AllocationFailed {
                additional: output_len,
            })?;
        self.budget.commit(budget_used);
        output.push_str(prefix);
        if let Some(return_type) = function.and_then(|value| value.return_type) {
            self.push_type_text(&mut output, return_type)?;
            output.push(' ');
        }
        self.push_components(&mut output, &name.components)?;
        if let Some(function) = function {
            output.push('(');
            for (index, argument) in function.arguments.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                self.push_type_text(&mut output, *argument)?;
            }
            output.push(')');
            if name.const_this {
                output.push_str(" const");
            }
        }

        FunctionName::new(output, 0).map_err(|_| Failure::InvalidFunctionName)
    }

    fn render_standalone_type(
        &mut self,
        prefix: &'static str,
        ty: TypeId,
    ) -> Result<FunctionName, Failure> {
        let output_len = checked_output_add(prefix.len(), self.type_len(ty)?, self.limits.output)?;
        let budget_used = self.budget.preflight(output_len)?;
        let mut output = String::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| Failure::AllocationFailed {
                additional: output_len,
            })?;
        self.budget.commit(budget_used);
        output.push_str(prefix);
        self.push_type_text(&mut output, ty)?;
        FunctionName::new(output, 0).map_err(|_| Failure::InvalidFunctionName)
    }

    fn normalized_type_parts(&self, ty: TypeId) -> Result<(TypeId, Vec<Modifier>), Failure> {
        let mut modifiers = Vec::new();
        let mut current = ty;
        loop {
            let node = self
                .types
                .get(current)
                .ok_or(Failure::InvalidFunctionName)?;
            match node {
                TypeNode::Modified {
                    kind: Modifier::Reference,
                    inner,
                } => {
                    self.push_normalized_modifier(&mut modifiers, Modifier::Reference)?;
                    current = match self.types.get(*inner) {
                        Some(TypeNode::Modified {
                            kind: Modifier::Reference,
                            inner,
                        }) => *inner,
                        _ => *inner,
                    };
                }
                TypeNode::Modified { kind, .. } if kind.is_cv() => {
                    let run_start = modifiers.len();
                    while let Some(TypeNode::Modified { kind, inner }) = self.types.get(current) {
                        if !kind.is_cv() {
                            break;
                        }
                        if !modifiers[run_start..].contains(kind) {
                            self.push_normalized_modifier(&mut modifiers, *kind)?;
                        }
                        current = *inner;
                    }
                }
                TypeNode::Modified { kind, inner } => {
                    self.push_normalized_modifier(&mut modifiers, *kind)?;
                    current = *inner;
                }
                _ => return Ok((current, modifiers)),
            }
        }
    }

    fn push_normalized_modifier(
        &self,
        modifiers: &mut Vec<Modifier>,
        modifier: Modifier,
    ) -> Result<(), Failure> {
        let attempted = modifiers
            .len()
            .checked_add(1)
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if attempted > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted,
                limit: self.limits.components,
            });
        }
        modifiers
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        modifiers.push(modifier);
        Ok(())
    }

    fn type_len(&self, ty: TypeId) -> Result<usize, Failure> {
        let plan = self.type_render_plan(ty)?;
        self.render_plan_len(plan)
    }

    fn template_arg_len(&self, argument: TemplateArgId) -> Result<usize, Failure> {
        let mut plan = Vec::new();
        self.build_template_arg_plan(argument, &mut plan)?;
        self.render_plan_len(plan)
    }

    fn render_plan_len(&self, plan: Vec<TypeRenderPart<'a>>) -> Result<usize, Failure> {
        self.render_plan_slice_len(&plan)
    }

    fn render_plan_slice_len(&self, plan: &[TypeRenderPart<'a>]) -> Result<usize, Failure> {
        let mut length = 0usize;
        for part in plan.iter().copied() {
            let additional = match part {
                TypeRenderPart::Text(text) => text.len(),
                TypeRenderPart::Bytes(bytes) => bytes.len(),
                TypeRenderPart::Component(component) => {
                    self.validate_utf8(component)?;
                    component
                        .bytes
                        .len()
                        .checked_add(usize::from(component.destructor))
                        .ok_or(Failure::OutputLimitExceeded {
                            attempted: usize::MAX,
                            limit: self.limits.output,
                        })?
                }
                TypeRenderPart::Decimal(value) => decimal_len(value),
            };
            length = checked_output_add(length, additional, self.limits.output)?;
        }
        Ok(length)
    }

    fn push_type_text(&self, output: &mut String, ty: TypeId) -> Result<(), Failure> {
        self.push_render_plan(output, self.type_render_plan(ty)?)
    }

    fn push_template_arg_text(
        &self,
        output: &mut String,
        argument: TemplateArgId,
    ) -> Result<(), Failure> {
        let mut plan = Vec::new();
        self.build_template_arg_plan(argument, &mut plan)?;
        self.push_render_plan(output, plan)
    }

    fn push_render_plan(
        &self,
        output: &mut String,
        plan: Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        for part in plan {
            match part {
                TypeRenderPart::Text(text) => output.push_str(text),
                TypeRenderPart::Bytes(bytes) => {
                    let text =
                        std::str::from_utf8(bytes).map_err(|_| Failure::InvalidFunctionName)?;
                    output.push_str(text);
                }
                TypeRenderPart::Component(component) => {
                    self.push_component_text(output, component)?
                }
                TypeRenderPart::Decimal(value) => push_decimal(output, value),
            }
        }
        Ok(())
    }

    fn type_render_plan(&self, ty: TypeId) -> Result<Vec<TypeRenderPart<'a>>, Failure> {
        let mut plan = Vec::new();
        plan.try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        if self.type_requires_standalone_injection(ty)? {
            self.build_injected_type_plan(ty, plan)
        } else {
            self.build_type_plan(ty, &mut plan)?;
            Ok(plan)
        }
    }

    fn build_type_plan(
        &self,
        ty: TypeId,
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        let (base, modifiers) = self.normalized_type_parts(ty)?;
        self.build_type_plan_parts(base, &modifiers, plan)
    }

    fn build_type_plan_parts(
        &self,
        base: TypeId,
        modifiers: &[Modifier],
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        match *self.types.get(base).ok_or(Failure::InvalidFunctionName)? {
            TypeNode::Void => self.push_plan_text(plan, "void")?,
            TypeNode::Int => self.push_plan_text(plan, "int")?,
            TypeNode::Char => self.push_plan_text(plan, "char")?,
            TypeNode::Builtin(text) | TypeNode::Standard(text) => {
                self.push_plan_text(plan, text)?
            }
            TypeNode::Named { start, end } => self.build_components_plan(start, end, plan)?,
            TypeNode::VendorQualifier { qualifier, inner } => {
                self.build_type_plan(inner, plan)?;
                self.push_plan_text(plan, " ")?;
                let end = qualifier
                    .checked_add(1)
                    .ok_or(Failure::InvalidFunctionName)?;
                self.build_components_plan(qualifier, end, plan)?;
            }
            TypeNode::AppliedTemplate {
                template,
                arguments_start,
                arguments_end,
            } => {
                self.build_type_plan(template, plan)?;
                self.push_plan_text(plan, "<")?;
                let arguments = self
                    .template_args
                    .get(arguments_start..arguments_end)
                    .ok_or(Failure::InvalidFunctionName)?;
                for (index, argument) in arguments.iter().enumerate() {
                    if index != 0 {
                        self.push_plan_text(plan, ", ")?;
                    }
                    self.build_template_arg_plan(*argument, plan)?;
                }
                let close = if match arguments.last().copied() {
                    Some(argument) => self.template_arg_ends_with_close(argument)?,
                    None => false,
                } {
                    " >"
                } else {
                    ">"
                };
                self.push_plan_text(plan, close)?;
            }
            TypeNode::Array { .. } => self.build_array_plan(base, modifiers, plan)?,
            TypeNode::Function {
                return_type,
                arguments_start,
                arguments_end,
            } => self.build_function_plan(
                return_type,
                arguments_start,
                arguments_end,
                modifiers,
                None,
                &[],
                plan,
            )?,
            TypeNode::MemberPointer { class, member } => {
                self.build_member_pointer_plan(class, member, modifiers, plan)?
            }
            TypeNode::LocalName(expression) => self.build_expr_plan(expression, plan)?,
            TypeNode::Modified { .. } => return Err(Failure::InvalidFunctionName),
        }
        if !matches!(
            self.types.get(base),
            Some(
                TypeNode::Function { .. } | TypeNode::MemberPointer { .. } | TypeNode::Array { .. }
            )
        ) {
            self.push_modifier_plan(plan, modifiers)?;
        }
        Ok(())
    }

    fn build_member_pointer_plan(
        &self,
        class: TypeId,
        member: TypeId,
        outer_modifiers: &[Modifier],
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        let (member_base, member_modifiers) = self.normalized_type_parts(member)?;
        match *self
            .types
            .get(member_base)
            .ok_or(Failure::InvalidFunctionName)?
        {
            TypeNode::Function {
                return_type,
                arguments_start,
                arguments_end,
            } => self.build_function_plan(
                return_type,
                arguments_start,
                arguments_end,
                &member_modifiers,
                Some(class),
                outer_modifiers,
                plan,
            ),
            _ => {
                self.build_type_plan(member, plan)?;
                self.push_plan_text(plan, " ")?;
                self.build_class_plan(class, plan)?;
                self.push_plan_text(plan, "::*")?;
                self.push_modifier_plan(plan, outer_modifiers)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_function_plan(
        &self,
        return_type: TypeId,
        arguments_start: usize,
        arguments_end: usize,
        modifiers: &[Modifier],
        class: Option<TypeId>,
        outer_modifiers: &[Modifier],
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        self.build_type_plan(return_type, plan)?;
        self.push_plan_text(plan, " ")?;

        let mut function_qualifier_start = modifiers.len();
        while function_qualifier_start > 0
            && modifiers
                .get(function_qualifier_start - 1)
                .is_some_and(|modifier| modifier.is_cv())
        {
            function_qualifier_start -= 1;
        }
        let declarator_modifiers = modifiers
            .get(..function_qualifier_start)
            .ok_or(Failure::InvalidFunctionName)?;
        let has_declarator =
            class.is_some() || !declarator_modifiers.is_empty() || !outer_modifiers.is_empty();
        if has_declarator {
            self.push_plan_text(plan, "(")?;
            if let Some(class) = class {
                self.build_class_plan(class, plan)?;
                self.push_plan_text(plan, "::*")?;
            }
            self.push_modifier_plan(plan, declarator_modifiers)?;
            self.push_modifier_plan(plan, outer_modifiers)?;
            self.push_plan_text(plan, ")")?;
        }

        self.push_plan_text(plan, "(")?;
        let arguments = self
            .function_args
            .get(arguments_start..arguments_end)
            .ok_or(Failure::InvalidFunctionName)?;
        for (index, argument) in arguments.iter().enumerate() {
            if index != 0 {
                self.push_plan_text(plan, ", ")?;
            }
            self.build_type_plan(*argument, plan)?;
        }
        self.push_plan_text(plan, ")")?;
        let function_qualifiers = modifiers
            .get(function_qualifier_start..)
            .ok_or(Failure::InvalidFunctionName)?;
        self.push_modifier_plan(plan, function_qualifiers)
    }

    fn build_class_plan(
        &self,
        class: TypeId,
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        match self.types.get(class).ok_or(Failure::InvalidFunctionName)? {
            TypeNode::Named { start, end } => self.build_components_plan(*start, *end, plan),
            _ => Err(Failure::InvalidFunctionName),
        }
    }

    fn build_array_plan(
        &self,
        array: TypeId,
        modifiers: &[Modifier],
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        let mut element_qualifier_start = modifiers.len();
        while element_qualifier_start > 0
            && modifiers
                .get(element_qualifier_start - 1)
                .is_some_and(|modifier| modifier.is_cv())
        {
            element_qualifier_start -= 1;
        }
        let declarator_modifiers = modifiers
            .get(..element_qualifier_start)
            .ok_or(Failure::InvalidFunctionName)?;
        let outer_element_qualifiers = modifiers
            .get(element_qualifier_start..)
            .ok_or(Failure::InvalidFunctionName)?;

        let mut element_qualifiers = Vec::new();
        element_qualifiers
            .try_reserve_exact(outer_element_qualifiers.len())
            .map_err(|_| Failure::AllocationFailed {
                additional: outer_element_qualifiers.len(),
            })?;
        element_qualifiers.extend_from_slice(outer_element_qualifiers);

        let mut dimensions = Vec::new();
        let mut current = array;
        let mut remaining = self
            .types
            .len()
            .checked_add(1)
            .ok_or(Failure::InvalidFunctionName)?;
        let element = loop {
            remaining = remaining
                .checked_sub(1)
                .ok_or(Failure::InvalidFunctionName)?;
            let TypeNode::Array { dimension, element } = *self
                .types
                .get(current)
                .ok_or(Failure::InvalidFunctionName)?
            else {
                return Err(Failure::InvalidFunctionName);
            };
            let attempted =
                dimensions
                    .len()
                    .checked_add(1)
                    .ok_or(Failure::ComponentLimitExceeded {
                        attempted: usize::MAX,
                        limit: self.limits.components,
                    })?;
            if attempted > self.limits.components {
                return Err(Failure::ComponentLimitExceeded {
                    attempted,
                    limit: self.limits.components,
                });
            }
            dimensions
                .try_reserve(1)
                .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
            dimensions.push(dimension);

            let (element_base, nested_modifiers) = self.normalized_type_parts(element)?;
            if matches!(self.types.get(element_base), Some(TypeNode::Array { .. }))
                && nested_modifiers.iter().all(|modifier| modifier.is_cv())
            {
                let qualifier_count = nested_modifiers
                    .len()
                    .checked_add(element_qualifiers.len())
                    .ok_or(Failure::ComponentLimitExceeded {
                        attempted: usize::MAX,
                        limit: self.limits.components,
                    })?;
                if qualifier_count > self.limits.components {
                    return Err(Failure::ComponentLimitExceeded {
                        attempted: qualifier_count,
                        limit: self.limits.components,
                    });
                }
                let mut combined = Vec::new();
                combined.try_reserve_exact(qualifier_count).map_err(|_| {
                    Failure::AllocationFailed {
                        additional: qualifier_count,
                    }
                })?;
                combined.extend_from_slice(&nested_modifiers);
                combined.extend_from_slice(&element_qualifiers);
                element_qualifiers = combined;
                current = element_base;
            } else {
                break element;
            }
        };

        let (element_base, element_modifiers) = self.normalized_type_parts(element)?;
        let modifier_count = element_modifiers
            .len()
            .checked_add(element_qualifiers.len())
            .ok_or(Failure::ComponentLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.components,
            })?;
        if modifier_count > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted: modifier_count,
                limit: self.limits.components,
            });
        }
        let mut combined_modifiers = Vec::new();
        combined_modifiers
            .try_reserve_exact(modifier_count)
            .map_err(|_| Failure::AllocationFailed {
                additional: modifier_count,
            })?;
        for modifier in element_modifiers.iter().chain(element_qualifiers.iter()) {
            if !modifier.is_cv() || !combined_modifiers.contains(modifier) {
                combined_modifiers.push(*modifier);
            }
        }
        self.build_type_plan_parts(element_base, &combined_modifiers, plan)?;

        if declarator_modifiers.is_empty() {
            self.push_plan_text(plan, " ")?;
        } else {
            self.push_plan_text(plan, " (")?;
            self.push_modifier_plan(plan, declarator_modifiers)?;
            self.push_plan_text(plan, ") ")?;
        }
        for dimension in dimensions {
            self.push_plan_text(plan, "[")?;
            match dimension {
                ArrayDimension::Absent => {}
                ArrayDimension::Number(dimension) => {
                    self.push_plan_part(plan, TypeRenderPart::Decimal(dimension))?;
                }
                ArrayDimension::Expression(expression) => {
                    self.build_expr_plan(expression, plan)?;
                }
            }
            self.push_plan_text(plan, "]")?;
        }
        Ok(())
    }

    fn build_components_plan(
        &self,
        start: usize,
        end: usize,
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        self.build_component_slice_plan(self.named_components(start, end)?, plan)
    }

    fn build_component_slice_plan(
        &self,
        components: &[Component<'a>],
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        for (index, component) in components.iter().enumerate() {
            if index != 0 {
                self.push_plan_text(plan, "::")?;
            }
            self.push_plan_part(plan, TypeRenderPart::Component(*component))?;
            if let Some((arguments_start, arguments_end)) = component.template_args {
                self.push_plan_text(
                    plan,
                    if component.bytes.last() == Some(&b'<') {
                        " <"
                    } else {
                        "<"
                    },
                )?;
                let arguments = self
                    .template_args
                    .get(arguments_start..arguments_end)
                    .ok_or(Failure::InvalidFunctionName)?;
                for (argument_index, argument) in arguments.iter().enumerate() {
                    if argument_index != 0 {
                        self.push_plan_text(plan, ", ")?;
                    }
                    self.build_template_arg_plan(*argument, plan)?;
                }
                let close = if match arguments.last().copied() {
                    Some(argument) => self.template_arg_ends_with_close(argument)?,
                    None => false,
                } {
                    " >"
                } else {
                    ">"
                };
                self.push_plan_text(plan, close)?;
            }
        }
        Ok(())
    }

    fn template_arg_ends_with_close(&self, argument: TemplateArgId) -> Result<bool, Failure> {
        let TemplateArgId::Type(ty) = argument else {
            return Ok(false);
        };
        let (base, modifiers) = self.normalized_type_parts(ty)?;
        if !modifiers.is_empty() {
            return Ok(false);
        }
        match *self.types.get(base).ok_or(Failure::InvalidFunctionName)? {
            TypeNode::AppliedTemplate { .. } => Ok(true),
            TypeNode::Named { start, end } => self
                .named_components(start, end)?
                .last()
                .map(|component| component.template_args.is_some())
                .ok_or(Failure::InvalidFunctionName),
            TypeNode::VendorQualifier { qualifier, .. } => self
                .type_name_components
                .get(qualifier)
                .map(|component| component.template_args.is_some())
                .ok_or(Failure::InvalidFunctionName),
            _ => Ok(false),
        }
    }

    fn build_template_arg_plan(
        &self,
        argument: TemplateArgId,
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        match argument {
            TemplateArgId::Type(ty) => self.build_type_plan(ty, plan),
            TemplateArgId::Expr(expr) => self.build_expr_plan(expr, plan),
        }
    }

    fn build_expr_plan(
        &self,
        expr: ExprId,
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        match *self
            .expressions
            .get(expr)
            .ok_or(Failure::InvalidFunctionName)?
        {
            ExprNode::IntegralLiteral {
                ty,
                digits,
                offset,
                negative,
            } => self.build_integral_literal_plan(ty, digits, offset, negative, plan),
            ExprNode::FloatingLiteral {
                ty,
                digits,
                negative,
            } => {
                self.push_plan_text(plan, "(")?;
                self.build_type_plan(ty, plan)?;
                if negative {
                    self.push_plan_text(plan, ")-[")?;
                } else {
                    self.push_plan_text(plan, ")[")?;
                }
                self.push_plan_part(plan, TypeRenderPart::Bytes(digits))?;
                self.push_plan_text(plan, "]")
            }
            ExprNode::Cast { ty, operand } => {
                self.push_plan_text(plan, "(")?;
                self.build_type_plan(ty, plan)?;
                self.push_plan_text(plan, ")(")?;
                self.build_expr_plan(operand, plan)?;
                self.push_plan_text(plan, ")")
            }
            ExprNode::Binary {
                operator,
                left,
                right,
            } => {
                if matches!(operator, BinaryOperator::Greater) {
                    self.push_plan_text(plan, "(")?;
                }
                self.push_plan_text(plan, "(")?;
                self.build_expr_plan(left, plan)?;
                self.push_plan_text(plan, ")")?;
                self.push_plan_text(
                    plan,
                    match operator {
                        BinaryOperator::Add => "+",
                        BinaryOperator::Greater => ">",
                    },
                )?;
                self.push_plan_text(plan, "(")?;
                self.build_expr_plan(right, plan)?;
                self.push_plan_text(plan, ")")?;
                if matches!(operator, BinaryOperator::Greater) {
                    self.push_plan_text(plan, ")")?;
                }
                Ok(())
            }
            ExprNode::Unary { operator, operand } => {
                match operator {
                    UnaryOperator::SizeOf => self.push_plan_text(plan, "sizeof (")?,
                    UnaryOperator::Negate => self.push_plan_text(plan, "-(")?,
                }
                self.build_expr_plan(operand, plan)?;
                self.push_plan_text(plan, ")")
            }
            ExprNode::ExternalName {
                components_start,
                components_end,
                arguments,
                const_this,
            } => {
                self.build_components_plan(components_start, components_end, plan)?;
                if let Some((start, end)) = arguments {
                    self.push_plan_text(plan, "(")?;
                    let arguments = self
                        .function_args
                        .get(start..end)
                        .ok_or(Failure::InvalidFunctionName)?;
                    for (index, argument) in arguments.iter().enumerate() {
                        if index != 0 {
                            self.push_plan_text(plan, ", ")?;
                        }
                        self.build_type_plan(*argument, plan)?;
                    }
                    self.push_plan_text(plan, ")")?;
                    if const_this {
                        self.push_plan_text(plan, " const")?;
                    }
                }
                Ok(())
            }
            ExprNode::ExternalLocalName {
                scope_components_start,
                scope_components_end,
                scope_arguments_start,
                scope_arguments_end,
                scope_const_this,
                entity_components_start,
                entity_components_end,
            } => {
                self.build_components_plan(scope_components_start, scope_components_end, plan)?;
                self.push_plan_text(plan, "(")?;
                let arguments = self
                    .function_args
                    .get(scope_arguments_start..scope_arguments_end)
                    .ok_or(Failure::InvalidFunctionName)?;
                for (index, argument) in arguments.iter().enumerate() {
                    if index != 0 {
                        self.push_plan_text(plan, ", ")?;
                    }
                    self.build_type_plan(*argument, plan)?;
                }
                self.push_plan_text(plan, ")")?;
                if scope_const_this {
                    self.push_plan_text(plan, " const")?;
                }
                self.push_plan_text(plan, "::")?;
                self.build_components_plan(entity_components_start, entity_components_end, plan)
            }
        }
    }

    fn build_integral_literal_plan(
        &self,
        ty: TypeId,
        digits: &'a [u8],
        offset: usize,
        negative: bool,
        plan: &mut Vec<TypeRenderPart<'a>>,
    ) -> Result<(), Failure> {
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Failure::InvalidTemplateArgument {
                offset,
                found: digits.iter().copied().find(|byte| !byte.is_ascii_digit()),
            });
        }

        let type_text = match self.types.get(ty).ok_or(Failure::InvalidFunctionName)? {
            TypeNode::Int => "int",
            TypeNode::Char => "char",
            TypeNode::Builtin(text) if is_integral_literal_type_name(text) => text,
            _ => return Err(Failure::InvalidFunctionName),
        };
        if type_text == "bool" && !negative && digits == b"0" {
            return self.push_plan_text(plan, "false");
        }
        if type_text == "bool" && !negative && digits == b"1" {
            return self.push_plan_text(plan, "true");
        }

        let suffix = match type_text {
            "int" => Some(""),
            "unsigned int" => Some("u"),
            "long" => Some("l"),
            "unsigned long" => Some("ul"),
            "long long" => Some("ll"),
            "unsigned long long" => Some("ull"),
            _ => None,
        };
        if suffix.is_none() {
            self.push_plan_text(plan, "(")?;
            self.build_type_plan(ty, plan)?;
            self.push_plan_text(plan, ")")?;
        }
        if negative {
            self.push_plan_text(plan, "-")?;
        }
        self.push_plan_part(plan, TypeRenderPart::Bytes(digits))?;
        if let Some(suffix) = suffix {
            self.push_plan_text(plan, suffix)?;
        }
        Ok(())
    }

    fn push_modifier_plan(
        &self,
        plan: &mut Vec<TypeRenderPart<'a>>,
        modifiers: &[Modifier],
    ) -> Result<(), Failure> {
        for modifier in modifiers.iter().rev() {
            self.push_plan_text(plan, modifier.suffix())?;
        }
        Ok(())
    }

    fn push_plan_text(
        &self,
        plan: &mut Vec<TypeRenderPart<'a>>,
        text: &'static str,
    ) -> Result<(), Failure> {
        self.push_plan_part(plan, TypeRenderPart::Text(text))
    }

    fn push_plan_part(
        &self,
        plan: &mut Vec<TypeRenderPart<'a>>,
        part: TypeRenderPart<'a>,
    ) -> Result<(), Failure> {
        let attempted = plan
            .len()
            .checked_add(1)
            .ok_or(Failure::OutputLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.output,
            })?;
        if attempted > self.limits.output {
            return Err(Failure::OutputLimitExceeded {
                attempted,
                limit: self.limits.output,
            });
        }
        plan.try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        plan.push(part);
        Ok(())
    }

    fn named_components(&self, start: usize, end: usize) -> Result<&[Component<'a>], Failure> {
        self.type_name_components
            .get(start..end)
            .ok_or(Failure::InvalidFunctionName)
    }

    fn resolve_conversion_type(&self, component: Component<'a>) -> Result<Option<TypeId>, Failure> {
        match component.conversion {
            None => Ok(None),
            Some(ConversionTarget::Type(type_id)) => Ok(Some(type_id)),
            Some(ConversionTarget::SelfTemplateParam(index)) => {
                let (start, end) = component
                    .template_args
                    .ok_or(Failure::InvalidFunctionName)?;
                let available = end.saturating_sub(start);
                let arena_index =
                    start
                        .checked_add(index)
                        .ok_or(Failure::TemplateParameterOverflow {
                            start: component.offset,
                            offset: component.offset,
                        })?;
                if arena_index >= end {
                    return Err(Failure::TemplateParameterOutOfRange {
                        offset: component.offset,
                        index,
                        available,
                    });
                }
                match self.template_args.get(arena_index).copied() {
                    Some(TemplateArgId::Type(type_id)) => Ok(Some(type_id)),
                    _ => Err(Failure::InvalidFunctionName),
                }
            }
        }
    }

    fn components_len(&self, components: &[Component<'a>]) -> Result<usize, Failure> {
        let mut length = 0;
        for (index, component) in components.iter().enumerate() {
            self.validate_utf8(*component)?;
            if index != 0 {
                length = checked_output_add(length, 2, self.limits.output)?;
            }
            if component.destructor {
                length = checked_output_add(length, 1, self.limits.output)?;
            }
            length = checked_output_add(length, component.bytes.len(), self.limits.output)?;
            if let Some(type_id) = self.resolve_conversion_type(*component)? {
                length = checked_output_add(length, self.type_len(type_id)?, self.limits.output)?;
            }
            if let Some((start, end)) = component.template_args {
                if component.bytes.last() == Some(&b'<') {
                    length = checked_output_add(length, 1, self.limits.output)?;
                }
                length = checked_output_add(length, 2, self.limits.output)?;
                let arguments = self
                    .template_args
                    .get(start..end)
                    .ok_or(Failure::InvalidFunctionName)?;
                for (argument_index, argument) in arguments.iter().enumerate() {
                    if argument_index != 0 {
                        length = checked_output_add(length, 2, self.limits.output)?;
                    }
                    length = checked_output_add(
                        length,
                        self.template_arg_len(*argument)?,
                        self.limits.output,
                    )?;
                }
                if match arguments.last().copied() {
                    Some(argument) => self.template_arg_ends_with_close(argument)?,
                    None => false,
                } {
                    length = checked_output_add(length, 1, self.limits.output)?;
                }
            }
        }
        Ok(length)
    }

    fn push_components(
        &self,
        output: &mut String,
        components: &[Component<'a>],
    ) -> Result<(), Failure> {
        for (index, component) in components.iter().enumerate() {
            if index != 0 {
                output.push_str("::");
            }
            self.push_component_text(output, *component)?;
            if let Some(type_id) = self.resolve_conversion_type(*component)? {
                self.push_type_text(output, type_id)?;
            }
            if let Some((start, end)) = component.template_args {
                let arguments = self
                    .template_args
                    .get(start..end)
                    .ok_or(Failure::InvalidFunctionName)?;
                if output.ends_with('<') {
                    output.push(' ');
                }
                output.push('<');
                for (argument_index, argument) in arguments.iter().enumerate() {
                    if argument_index != 0 {
                        output.push_str(", ");
                    }
                    self.push_template_arg_text(output, *argument)?;
                }
                if match arguments.last().copied() {
                    Some(argument) => self.template_arg_ends_with_close(argument)?,
                    None => false,
                } {
                    output.push(' ');
                }
                output.push('>');
            }
        }
        Ok(())
    }

    fn byte(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn peek(&self, ahead: usize) -> Option<u8> {
        self.position
            .checked_add(ahead)
            .and_then(|offset| self.input.get(offset))
            .copied()
    }

    fn component_vec(&self) -> Result<Vec<Component<'a>>, Failure> {
        let mut components = Vec::new();
        components
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        Ok(components)
    }

    fn standard_component(&self) -> Component<'static> {
        Component {
            bytes: b"std",
            offset: self.position,
            template_args: None,
            destructor: false,
            conversion: None,
        }
    }

    fn push_component(
        &mut self,
        components: &mut Vec<Component<'a>>,
        component: Component<'a>,
    ) -> Result<(), Failure> {
        self.add_component()?;
        self.push_existing_component(components, component)
    }

    fn push_existing_component(
        &self,
        components: &mut Vec<Component<'a>>,
        component: Component<'a>,
    ) -> Result<(), Failure> {
        components
            .try_reserve(1)
            .map_err(|_| Failure::AllocationFailed { additional: 1 })?;
        components.push(component);
        Ok(())
    }

    fn add_component(&mut self) -> Result<(), Failure> {
        let attempted =
            self.component_count
                .checked_add(1)
                .ok_or(Failure::ComponentLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.components,
                })?;
        if attempted > self.limits.components {
            return Err(Failure::ComponentLimitExceeded {
                attempted,
                limit: self.limits.components,
            });
        }
        self.component_count = attempted;
        Ok(())
    }

    fn enter_depth(&mut self) -> Result<usize, Failure> {
        let original = self.depth;
        let attempted = original
            .checked_add(1)
            .ok_or(Failure::NestingLimitExceeded {
                attempted: usize::MAX,
                limit: self.limits.depth,
            })?;
        if attempted > self.limits.depth {
            return Err(Failure::NestingLimitExceeded {
                attempted,
                limit: self.limits.depth,
            });
        }
        self.depth = attempted;
        Ok(original)
    }

    fn validate_utf8(&self, component: Component<'a>) -> Result<(), Failure> {
        std::str::from_utf8(component.bytes)
            .map(|_| ())
            .map_err(|error| Failure::InvalidUtf8 {
                offset: component.offset.saturating_add(error.valid_up_to()),
            })
    }

    fn push_component_text(
        &self,
        output: &mut String,
        component: Component<'a>,
    ) -> Result<(), Failure> {
        let text = std::str::from_utf8(component.bytes).map_err(|error| Failure::InvalidUtf8 {
            offset: component.offset.saturating_add(error.valid_up_to()),
        })?;
        if component.destructor {
            output.push('~');
        }
        output.push_str(text);
        Ok(())
    }
}

fn builtin_type_name(code: u8) -> Option<&'static str> {
    match code {
        b'v' => Some("void"),
        b'w' => Some("wchar_t"),
        b'b' => Some("bool"),
        b'c' => Some("char"),
        b'a' => Some("signed char"),
        b'h' => Some("unsigned char"),
        b's' => Some("short"),
        b't' => Some("unsigned short"),
        b'i' => Some("int"),
        b'j' => Some("unsigned int"),
        b'l' => Some("long"),
        b'm' => Some("unsigned long"),
        b'x' => Some("long long"),
        b'y' => Some("unsigned long long"),
        b'n' => Some("__int128"),
        b'o' => Some("unsigned __int128"),
        b'f' => Some("float"),
        b'd' => Some("double"),
        b'e' => Some("long double"),
        b'g' => Some("__float128"),
        b'z' => Some("..."),
        _ => None,
    }
}

fn is_integral_literal_type(code: u8) -> bool {
    matches!(
        code,
        b'w' | b'b'
            | b'c'
            | b'a'
            | b'h'
            | b's'
            | b't'
            | b'i'
            | b'j'
            | b'l'
            | b'm'
            | b'x'
            | b'y'
            | b'n'
            | b'o'
    )
}

fn is_integral_literal_type_name(name: &str) -> bool {
    matches!(
        name,
        "wchar_t"
            | "bool"
            | "signed char"
            | "unsigned char"
            | "short"
            | "unsigned short"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "__int128"
            | "unsigned __int128"
    )
}

fn decimal_len(mut value: usize) -> usize {
    let mut length = 1usize;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

fn push_decimal(output: &mut String, mut value: usize) {
    let mut digits = [0u8; 20];
    let mut position = digits.len();
    loop {
        position -= 1;
        digits[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if let Some(decimal) = digits.get(position..) {
        for digit in decimal {
            output.push(char::from(*digit));
        }
    }
}

fn checked_output_add(current: usize, additional: usize, limit: usize) -> Result<usize, Failure> {
    let attempted = current
        .checked_add(additional)
        .ok_or(Failure::OutputLimitExceeded {
            attempted: usize::MAX,
            limit,
        })?;
    if attempted > limit {
        return Err(Failure::OutputLimitExceeded { attempted, limit });
    }
    Ok(attempted)
}

#[cfg(test)]
mod tests {
    use super::{
        demangle, demangle_with_limits, AttemptBudget, Component, DeclaratorInvocation, Failure,
        Limits, Parser, TemplateArgId, TestLimits, TypeNode,
    };
    use crate::limits::{MAX_COMPONENTS, MAX_INPUT_BYTES, MAX_NESTING_DEPTH, MAX_OUTPUT_BYTES};

    const GOLDEN: &[(&[u8], &str)] = &[
        (b"_Z1fv", "f()"),
        (b"_Z1fi", "f(int)"),
        (b"_Z3fooc", "foo(char)"),
        (b"_Z3foo3bar", "foo(bar)"),
        (b"_ZN1N1fE", "N::f"),
        (b"_ZN6System5Sound4beepEv", "System::Sound::beep()"),
        (b"_ZN5Arena5levelE", "Arena::level"),
        (b"_ZSt5state", "std::state"),
        (b"_ZNSt3_In4wardE", "std::_In::ward"),
        (b"_ZN1f1fE", "f::f"),
        (
            b"_ZNK10QTableView14verticalHeaderEv",
            "QTableView::verticalHeader() const",
        ),
        (
            b"_ZNK12QTableWidget20horizontalHeaderItemEi",
            "QTableWidget::horizontalHeaderItem(int) const",
        ),
    ];

    fn rejects(input: &[u8]) {
        assert!(demangle(input).is_err(), "unexpectedly accepted {input:?}");
    }

    fn parser_with_test_limits(input: &[u8], test_limits: TestLimits) -> Parser<'_> {
        let limits = Limits {
            output: test_limits.output,
            budget: test_limits.budget,
            components: test_limits.components,
            backreferences: test_limits.backreferences,
            depth: test_limits.depth,
            initial_depth: test_limits.initial_depth,
            ..Limits::default()
        };
        Parser {
            input,
            position: 0,
            limits,
            component_count: 0,
            depth: test_limits.initial_depth,
            budget: AttemptBudget::new(test_limits.budget),
            types: Vec::new(),
            function_args: Vec::new(),
            type_name_components: Vec::new(),
            substitutions: Vec::new(),
            template_args: Vec::new(),
            expressions: Vec::new(),
            in_progress_template_scopes: Vec::new(),
            active_template_scope: None,
        }
    }

    fn decode_fixture_string(field: &str) -> Result<String, &'static str> {
        if field.len() > MAX_OUTPUT_BYTES {
            return Err("fixture field exceeds decoder bound");
        }
        let body = field
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or("fixture field is not quoted")?;
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

    #[test]
    fn gnu_fixture_matches_all_authoritative_rows_exactly() {
        let mut total = 0usize;
        let mut exact = 0usize;
        let mut rejected = 0usize;
        let mut mismatch = 0usize;
        let mut examples = Vec::new();
        examples.try_reserve_exact(40).expect("bounded diagnostics");
        for line in include_str!("../../tests/fixtures/cpp_demangle.tsv").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let mut fields = line.split('\t');
            let raw_field = fields.next().expect("fixture raw field");
            let route = fields.next().expect("fixture route field");
            let expected_field = fields.next().expect("fixture expected field");
            assert!(fields.next().is_none(), "fixture row has extra fields");
            if route != "gnu-v3" {
                continue;
            }
            total += 1;
            let raw = decode_fixture_string(raw_field).expect("valid raw fixture string");
            let expected =
                decode_fixture_string(expected_field).expect("valid expected fixture string");
            match demangle(raw.as_bytes()) {
                Ok(actual) if actual.name() == expected => exact += 1,
                Ok(actual) => {
                    mismatch += 1;
                    if examples.len() < 40 {
                        examples.push(format!(
                            "mismatch raw={raw:?} expected={expected:?} actual={:?}",
                            actual.name()
                        ));
                    }
                }
                Err(error) => {
                    rejected += 1;
                    if examples.len() < 40 {
                        examples.push(format!("rejected raw={raw:?} error={error:?}"));
                    }
                }
            }
        }
        assert_eq!(total, 93);
        println!(
            "GNU fixture: exact={exact}/{total}, rejected={rejected}, mismatch={mismatch}; examples={examples:#?}"
        );
        assert_eq!(exact, 93, "all GNU rows must remain exact");
        assert_eq!(rejected, 0, "no GNU oracle row may be rejected");
        assert_eq!(mismatch, 0, "accepted GNU rows must remain exact");
    }

    #[test]
    fn parser_matches_all_twelve_representative_golden_rows() {
        assert_eq!(GOLDEN.len(), 12);
        for &(raw, expected) in GOLDEN {
            let actual = demangle(raw).expect("golden GNU v3 row must parse");
            assert_eq!(actual.full_name(), expected, "raw={raw:?}");
            assert_eq!(actual.name(), expected, "selector must start at byte zero");
        }
    }

    #[test]
    fn unary_substitution_standard_and_operator_rows_match_authoritative_oracle() {
        for (raw, expected) in [
            (b"_ZN9QSettings10beginGroupERK7QString".as_slice(), "QSettings::beginGroup(QString const&)"),
            (b"_Zrm1XS_", "operator%(X, X)"),
            (b"_ZplR1XS0_", "operator+(X&, X&)"),
            (b"_ZlsRK1XS1_", "operator<<(X const&, X const&)"),
            (b"_ZlsRSoRKSs", "operator<<(std::ostream&, std::string const&)"),
            (b"_Z3foo5Hello5WorldS0_S_", "foo(Hello, World, World, Hello)"),
            (
                b"_Z3fooiPiPS_PS0_PS1_PS2_PS3_PS4_PS5_PS6_PS7_PS8_PS9_PSA_PSB_PSC_",
                "foo(int, int*, int**, int***, int****, int*****, int******, int*******, int********, int*********, int**********, int***********, int************, int*************, int**************, int***************)",
            ),
        ] {
            let actual = demangle(raw).expect("approved GNU v3 row must parse");
            assert_eq!(actual.name(), expected, "raw={raw:?}");
        }
    }

    #[test]
    fn function_and_member_pointer_declarators_match_bundled_printer() {
        for (raw, expected) in [
            (
                b"_Z3fooIiFvdEiEvv".as_slice(),
                "void foo<int, void (double), int>()",
            ),
            (b"_Z3fooPM2ABi", "foo(int AB::**)"),
            (b"_Z1fM1AKFvvE", "f(void (A::*)() const)"),
            (b"_Z1fPFvvEM1SFvvE", "f(void (*)(), void (S::*)())"),
            (b"_Z1fKPFiiE", "f(int (* const)(int))"),
        ] {
            assert_eq!(
                demangle(raw)
                    .expect("function/member declarator oracle")
                    .name(),
                expected,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn member_function_wrapper_candidates_follow_bundled_source_order() {
        let input = b"_ZN12libcw_app_ct10add_optionIS_EEvMT_FvPKcES3_cS3_S3_";
        let mut parser = parser_with_test_limits(input, TestLimits::default());
        parser.position = 2;
        let name = parser.parse_name().expect("nested template name");
        parser.active_template_scope = name.template_scope;
        let function = parser
            .parse_bare_function_type(true)
            .expect("member-function-pointer signature");

        let mut candidates = Vec::new();
        for &candidate in &parser.substitutions {
            let mut text = String::new();
            parser
                .push_type_text(&mut text, candidate)
                .expect("candidate renders");
            candidates.push(text);
        }
        assert_eq!(
            candidates,
            [
                "libcw_app_ct",
                "libcw_app_ct::add_option",
                "libcw_app_ct",
                "char const",
                "char const*",
                "void (char const*)",
                "void (libcw_app_ct::*)(char const*)",
            ]
        );
        assert_eq!(function.arguments.len(), 5);
        assert_eq!(
            demangle(input)
                .expect("authoritative member-pointer substitution row")
                .name(),
            "void libcw_app_ct::add_option<libcw_app_ct>(void (libcw_app_ct::*)(char const*), char const*, char, char const*, char const*)"
        );
    }

    #[test]
    fn newly_supported_named_declarator_shapes_validate_before_public_output() {
        for raw in [
            b"_Z10hairyfunc5PFPFilEPcE".as_slice(),
            b"_ZNK1C1fIiEEPFivEv",
            b"_Z1fIiEM1CFivEv",
        ] {
            assert!(demangle(raw).is_ok(), "raw={raw:?}");
        }
    }

    #[test]
    fn declarator_validation_reaches_every_name_component_template_argument() {
        for raw in [
            b"_Z1fIFPFivEvEEvv".as_slice(),
            b"_Z1fIFM1CFivEvEEvv",
            b"1AIFPFivEvEE",
            b"1AIFM1CFivEvEE",
            b"_ZTI1AIFPFivEvEE",
            b"_ZTI1AIFM1CFivEvEE",
            b"_ZN1AIFPFivEvEE1fEv",
            b"Fv1AIFPFivEvEEE",
            b"U1xIFPFivEvEEi",
            b"U1xIFM1CFivEvEEi",
        ] {
            assert!(demangle(raw).is_ok(), "raw={raw:?}");
        }

        assert!(matches!(
            demangle_with_limits(
                b"_Z1fIFPFivEvEEvv",
                TestLimits {
                    output: 0,
                    budget: 0,
                    ..TestLimits::default()
                }
            ),
            Err(Failure::OutputLimitExceeded { .. }) | Err(Failure::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn directly_renderable_name_template_argument_declarators_remain_supported() {
        for (raw, expected) in [
            (b"_Z1fIFivEEvv".as_slice(), "void f<int ()>()"),
            (b"_Z1fIPFivEEvv", "void f<int (*)()>()"),
            (b"_Z1fIM1CFivEEvv", "void f<int (C::*)()>()"),
            (b"1AIFivEE", "A<int ()>"),
            (b"1AIPFivEE", "A<int (*)()>"),
            (b"1AIM1CFivEE", "A<int (C::*)()>"),
            (b"_ZTI1AIFivEE", "typeinfo for A<int ()>"),
            (b"_ZTI1AIPFivEE", "typeinfo for A<int (*)()>"),
            (b"_ZTI1AIM1CFivEE", "typeinfo for A<int (C::*)()>"),
        ] {
            assert_eq!(
                demangle(raw).expect("supported template declarator").name(),
                expected,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn newly_supported_standalone_declarator_shapes_validate_before_public_output() {
        for raw in [
            b"FPFivEvE".as_slice(),
            b"_ZTIFPFivEvE",
            b"FM1CFivEvE",
            b"_ZTIFM1CFivEvE",
            b"_Z1fFPFivEvE",
            b"_Z1fFM1CFivEvE",
            b"M1CM1DFivE",
            b"A1_FivE",
        ] {
            assert!(demangle(raw).is_ok(), "raw={raw:?}");
        }
    }

    #[test]
    fn direct_standalone_function_declarators_remain_supported() {
        for (raw, expected) in [
            (b"FivE".as_slice(), "int ()"),
            (b"_ZTIFivE", "typeinfo for int ()"),
            (b"PFivE", "int (*)()"),
            (b"_ZTIPFivE", "typeinfo for int (*)()"),
            (b"M1CFivE", "int (C::*)()"),
            (b"_ZTIM1CFivE", "typeinfo for int (C::*)()"),
        ] {
            assert_eq!(
                demangle(raw)
                    .expect("supported standalone declarator")
                    .name(),
                expected,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn template_type_arguments_arrays_params_and_function_returns_match_oracle() {
        for (raw, expected) in [
            (b"_ZN3FooIA4_iE3barE".as_slice(), "Foo<int [4]>::bar"),
            (b"_Z1fIiEvi", "void f<int>(int)"),
            (b"_Z5firstI3DuoEvS0_", "void first<Duo>(Duo)"),
            (b"_Z5firstI3DuoEvT_", "void first<Duo>(Duo)"),
            (b"_ZN5StackIiiE5levelE", "Stack<int, int>::level"),
        ] {
            assert_eq!(demangle(raw).expect("template oracle").name(), expected);
        }
    }

    #[test]
    fn integral_non_type_template_literals_match_bundled_printer() {
        for (raw, expected) in [
            (b"_Z3absILi11EEvv".as_slice(), "void abs<11>()"),
            (b"_Z1fILin1EEvv", "void f<-1>()"),
            (b"_Z1fILb0EEvv", "void f<false>()"),
            (b"_Z1fILb1EEvv", "void f<true>()"),
            (b"_Z1fILb2EEvv", "void f<(bool)2>()"),
            (b"_Z1fILc120EEvv", "void f<(char)120>()"),
            (b"_Z1fILa120EEvv", "void f<(signed char)120>()"),
            (b"_Z1fILh120EEvv", "void f<(unsigned char)120>()"),
            (b"_Z1fILs120EEvv", "void f<(short)120>()"),
            (b"_Z1fILt120EEvv", "void f<(unsigned short)120>()"),
            (b"_Z1fILj12EEvv", "void f<12u>()"),
            (b"_Z1fILl12EEvv", "void f<12l>()"),
            (b"_Z1fILm12EEvv", "void f<12ul>()"),
            (b"_Z1fILx12EEvv", "void f<12ll>()"),
            (b"_Z1fILy12EEvv", "void f<12ull>()"),
            (b"_Z1fILw12EEvv", "void f<(wchar_t)12>()"),
            (b"_Z1fILn12EEvv", "void f<(__int128)12>()"),
            (b"_Z1fILo12EEvv", "void f<(unsigned __int128)12>()"),
        ] {
            assert_eq!(
                demangle(raw).expect("integral literal oracle").name(),
                expected,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn integral_literal_digits_are_borrowed_and_not_machine_sized() {
        let digits = "1234567890".repeat(300);
        let raw = format!("_Z1fILi{digits}EEvv");
        let expected = format!("void f<{digits}>()");
        assert_eq!(
            demangle(raw.as_bytes())
                .expect("arbitrary digit span")
                .name(),
            expected
        );
    }

    #[test]
    fn literal_template_args_resolve_directly_in_template_argument_position() {
        assert_eq!(
            demangle(b"_Z1fILi1EiT0_Evv")
                .expect("type argument after literal remains in template scope")
                .name(),
            "void f<1, int, int>()"
        );
        assert_eq!(
            demangle(b"_Z1fILi1ET_Evv")
                .expect("direct literal template parameter")
                .name(),
            "void f<1, 1>()"
        );
        assert_eq!(
            demangle(b"_Z1fILi1ELi2ET0_Evv")
                .expect("indexed direct literal template parameter")
                .name(),
            "void f<1, 2, 2>()"
        );
        assert_eq!(
            demangle(b"_Z1fILi1EEv1AIT_E")
                .expect("direct literal from stable template scope")
                .name(),
            "void f<1>(A<1>)"
        );

        let mut parser = parser_with_test_limits(b"_Z1fILi1ET_Evv", TestLimits::default());
        parser
            .parse_mangled_name()
            .expect("direct literal template parameter parse");
        assert_eq!(parser.expressions.len(), 1);
        assert!(matches!(
            parser.template_args.as_slice(),
            [TemplateArgId::Expr(first), TemplateArgId::Expr(second)] if first == second
        ));
    }

    #[test]
    fn expression_template_parameters_remain_rejected_in_type_contexts() {
        for raw in [
            b"_Z1fILi1EEvT_".as_slice(),
            b"_Z1fILi1EEvPT_",
            b"_Z1fILi1EEvKT_",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn malformed_and_unsupported_literal_boundaries_fail_closed() {
        for raw in [
            b"_Z1fIL".as_slice(),
            b"_Z1fILEEvv",
            b"_Z1fILi",
            b"_Z1fILiE",
            b"_Z1fILiEEvv",
            b"_Z1fILinEEvv",
            b"_Z1fILinn1EEvv",
            b"_Z1fILi1xEEvv",
            b"_Z1fILi1",
            b"_Z1fILi1E",
            b"_Z1fILv1EEvv",
            b"_Z1fIplLi1ELi2EEvv",
            b"_Z1fILi1ETEEvv",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn literal_depth_restores_on_success_error_and_limit_rejection() {
        let exact = TestLimits {
            initial_depth: MAX_NESTING_DEPTH - 2,
            ..TestLimits::default()
        };
        assert!(demangle_with_limits(b"_Z1fILi1EEvv", exact).is_ok());

        let over = TestLimits {
            initial_depth: MAX_NESTING_DEPTH - 1,
            ..TestLimits::default()
        };
        assert!(matches!(
            demangle_with_limits(b"_Z1fILi1EEvv", over),
            Err(Failure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH
            }) if attempted == MAX_NESTING_DEPTH + 1
        ));

        let mut malformed = parser_with_test_limits(b"_Z1fILi1xEEvv", TestLimits::default());
        assert!(malformed.parse_mangled_name().is_err());
        assert_eq!(malformed.depth, 0);
        assert!(malformed.in_progress_template_scopes.is_empty());
        assert!(malformed.template_args.is_empty());
        assert!(malformed.expressions.is_empty());
    }

    #[test]
    fn integral_literal_output_budget_and_component_cap_are_exact() {
        let expected = "void f<(signed char)-120>()";
        let exact = TestLimits {
            output: expected.len(),
            budget: expected.len(),
            components: 4,
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(b"_Z1fILan120EEvv", exact)
                .expect("exact literal limits")
                .name(),
            expected
        );
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILan120EEvv",
                TestLimits {
                    output: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::OutputLimitExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILan120EEvv",
                TestLimits {
                    budget: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::BudgetExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILan120EEvv",
                TestLimits {
                    components: 3,
                    ..exact
                }
            ),
            Err(Failure::ComponentLimitExceeded { .. })
        ));
    }

    #[test]
    fn direct_expression_template_parameter_limits_are_exact() {
        let expected = "void f<1, 1>()";
        let exact = TestLimits {
            output: expected.len(),
            budget: expected.len(),
            components: 6,
            initial_depth: MAX_NESTING_DEPTH - 2,
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(b"_Z1fILi1ET_Evv", exact)
                .expect("exact direct expression parameter limits")
                .name(),
            expected
        );
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILi1ET_Evv",
                TestLimits {
                    output: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::OutputLimitExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILi1ET_Evv",
                TestLimits {
                    budget: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::BudgetExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILi1ET_Evv",
                TestLimits {
                    components: 5,
                    ..exact
                }
            ),
            Err(Failure::ComponentLimitExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"_Z1fILi1ET_Evv",
                TestLimits {
                    initial_depth: MAX_NESTING_DEPTH - 1,
                    ..exact
                }
            ),
            Err(Failure::NestingLimitExceeded { .. })
        ));
    }

    #[test]
    fn only_a_templated_function_name_component_implies_a_return_type() {
        assert_eq!(
            demangle(b"_ZN3FooIiE3barEv")
                .expect("class-template member function")
                .name(),
            "Foo<int>::bar()"
        );
    }

    #[test]
    fn nested_templated_prefix_substitutions_follow_source_order() {
        for (raw, expected) in [
            (
                b"_ZN3FooIiE3BarIS_E3bazE".as_slice(),
                "Foo<int>::Bar<Foo>::baz",
            ),
            (b"_ZN3FooIiE3BarIS0_E3bazE", "Foo<int>::Bar<Foo<int> >::baz"),
            (
                b"_ZN3FooIiE3BarIS1_E3bazE",
                "Foo<int>::Bar<Foo<int>::Bar>::baz",
            ),
            (
                b"_ZN3FooIiE3BarIS0_E3BazIS2_E3quxE",
                "Foo<int>::Bar<Foo<int> >::Baz<Foo<int>::Bar<Foo<int> > >::qux",
            ),
        ] {
            assert_eq!(
                demangle(raw).expect("qualified substitution").name(),
                expected
            );
        }

        assert!(matches!(
            demangle(b"_ZN3FooIiE3BarIS2_E3bazE"),
            Err(Failure::SubstitutionOutOfRange {
                index: 3,
                available: 3,
                ..
            })
        ));
    }

    #[test]
    fn recursive_template_argument_ranges_are_logically_scoped() {
        for (raw, expected) in [
            (b"_Z1fIiT_Evv".as_slice(), "void f<int, int>()"),
            (b"_Z1fI3FooIiET_Evv", "void f<Foo<int>, Foo<int> >()"),
            (b"_Z1fI3FooIiEEvv", "void f<Foo<int> >()"),
            (b"_Z1fI3FooIiEEvT_", "void f<Foo<int> >(Foo<int>)"),
            (b"_Z1fI3BarIiEEvv", "void f<Bar<int> >()"),
            (b"_Z1fI3BarIiEEvT_", "void f<Bar<int> >(Bar<int>)"),
            (b"_Z1fILi1E3FooILi2ET_ET_Evv", "void f<1, Foo<2, 2>, 1>()"),
            (b"_Z1fI1XEvPVN1AIT_E1TE", "void f<X>(A<X>::T volatile*)"),
        ] {
            assert_eq!(
                demangle(raw).expect("nested template list").name(),
                expected
            );
        }
    }

    #[test]
    fn in_progress_template_scopes_restore_and_enforce_depth_and_argument_caps() {
        fn nested_template_args(scope_count: usize) -> Vec<u8> {
            let mut input = Vec::new();
            input
                .try_reserve(scope_count.saturating_mul(4))
                .expect("bounded test input");
            input.push(b'I');
            for _ in 1..scope_count {
                input.extend_from_slice(b"1AI");
            }
            input.push(b'i');
            input.extend(std::iter::repeat_n(b'E', scope_count));
            input
        }

        let exact_input = nested_template_args(MAX_NESTING_DEPTH);
        let mut exact = parser_with_test_limits(&exact_input, TestLimits::default());
        assert!(exact.parse_template_args().is_ok());
        assert!(exact.in_progress_template_scopes.is_empty());
        assert_eq!(exact.depth, 0);

        let over_input = nested_template_args(MAX_NESTING_DEPTH + 1);
        let mut over = parser_with_test_limits(&over_input, TestLimits::default());
        assert!(matches!(
            over.parse_template_args(),
            Err(Failure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH
            }) if attempted == MAX_NESTING_DEPTH + 1
        ));
        assert!(over.in_progress_template_scopes.is_empty());
        assert_eq!(over.depth, 0);
        assert!(over.template_args.is_empty());

        let argument_limits = TestLimits {
            components: 3,
            ..TestLimits::default()
        };
        let mut exact_args = parser_with_test_limits(b"IiiiE", argument_limits);
        assert_eq!(exact_args.parse_template_args(), Ok((0, 3)));
        assert!(exact_args.in_progress_template_scopes.is_empty());

        let mut over_args = parser_with_test_limits(b"IiiiiE", argument_limits);
        assert!(matches!(
            over_args.parse_template_args(),
            Err(Failure::ComponentLimitExceeded {
                attempted: 4,
                limit: 3
            })
        ));
        assert!(over_args.in_progress_template_scopes.is_empty());
        assert_eq!(over_args.depth, 0);
        assert!(over_args.template_args.is_empty());
    }

    #[test]
    fn in_progress_template_scope_errors_do_not_leak_nested_or_outer_state() {
        let mut nested_error = parser_with_test_limits(b"I1AIT_EE", TestLimits::default());
        assert!(matches!(
            nested_error.parse_template_args(),
            Err(Failure::TemplateParameterOutOfRange {
                index: 0,
                available: 0,
                ..
            })
        ));
        assert!(nested_error.in_progress_template_scopes.is_empty());
        assert_eq!(nested_error.depth, 0);
        assert!(nested_error.template_args.is_empty());

        assert!(matches!(
            demangle(b"_Z1fIiT0_Evv"),
            Err(Failure::TemplateParameterOutOfRange {
                index: 1,
                available: 1,
                ..
            })
        ));
        assert!(matches!(
            demangle(b"_Z1fILi1ET0_Evv"),
            Err(Failure::TemplateParameterOutOfRange {
                index: 1,
                available: 1,
                ..
            })
        ));
        assert!(matches!(
            demangle(b"_Z1fIT_Evv"),
            Err(Failure::TemplateParameterOutOfRange {
                index: 0,
                available: 0,
                ..
            })
        ));
    }

    #[test]
    fn modified_array_declarators_match_bundled_printer() {
        for (raw, expected) in [
            (b"_Z1fA37_iPS_".as_slice(), "f(int [37], int (*) [37])"),
            (b"_Z1sPA37_iPS0_", "s(int (*) [37], int (**) [37])"),
            (b"_Z3kooPA28_A30_i", "koo(int (*) [28][30])"),
            (
                b"_Z3fooIA6_KiEvA9_KT_rVPrS4_",
                "void foo<int const [6]>(int const [9][6], int restrict const (* volatile restrict) [9][6])",
            ),
            (b"_Z3fooIA3_iEvRKT_", "void foo<int [3]>(int const (&) [3])"),
            (
                b"_Z3fooIPA3_iEvRKT_",
                "void foo<int (*) [3]>(int (* const&) [3])",
            ),
        ] {
            assert_eq!(demangle(raw).expect("modified array").name(), expected);
        }
    }

    #[test]
    fn multidimensional_arrays_render_outer_to_inner_without_extra_spaces() {
        assert_eq!(
            demangle(b"_Z1fA4_A3_i")
                .expect("multidimensional array")
                .name(),
            "f(int [4][3])"
        );
        assert_eq!(
            demangle(b"_Z1fA4_iS_").expect("array substitution").name(),
            "f(int [4], int [4])"
        );
    }

    #[test]
    fn array_wrapper_depth_accepts_exact_and_rejects_one_over() {
        let exact = format!("_Z1f{}i", "A1_".repeat(MAX_NESTING_DEPTH));
        assert!(demangle(exact.as_bytes()).is_ok());

        let over = format!("_Z1f{}i", "A1_".repeat(MAX_NESTING_DEPTH + 1));
        assert!(matches!(
            demangle(over.as_bytes()),
            Err(Failure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH
            }) if attempted == MAX_NESTING_DEPTH + 1
        ));
    }

    #[test]
    fn malicious_array_chain_is_safe_on_64_kib_stack_subprocess() {
        const CHILD_ENV: &str = "VMP_GNU_ARRAY_SMALL_STACK_CHILD";
        const TEST_NAME: &str =
            "gnu_v3::tests::malicious_array_chain_is_safe_on_64_kib_stack_subprocess";

        if std::env::var_os(CHILD_ENV).is_some() {
            let child = std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(|| {
                    let wrapper_count = (MAX_INPUT_BYTES - 5) / 3;
                    let input = format!("_Z1f{}i", "A1_".repeat(wrapper_count));
                    assert!(input.len() <= MAX_INPUT_BYTES);
                    assert!(matches!(
                        demangle(input.as_bytes()),
                        Err(Failure::NestingLimitExceeded { .. })
                    ));
                })
                .expect("small-stack parser thread must start");
            child.join().expect("iterative array parser must not abort");
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
    fn adversarial_declarator_validation_is_safe_on_64_kib_stack_subprocess() {
        const CHILD_ENV: &str = "VMP_GNU_DECLARATOR_SMALL_STACK_CHILD";
        const TEST_NAME: &str =
            "gnu_v3::tests::adversarial_declarator_validation_is_safe_on_64_kib_stack_subprocess";

        if std::env::var_os(CHILD_ENV).is_some() {
            let child = std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(|| {
                    let limits = TestLimits {
                        depth: MAX_COMPONENTS,
                        ..TestLimits::default()
                    };
                    let mut deepest = parser_with_test_limits(b"", limits);
                    deepest
                        .types
                        .try_reserve_exact(MAX_COMPONENTS)
                        .expect("bounded adversarial type arena");
                    deepest.types.push(TypeNode::Int);
                    deepest.type_name_components.push(Component {
                        bytes: b"vendor",
                        offset: 0,
                        template_args: None,
                        destructor: false,
                        conversion: None,
                    });
                    for inner in 0..MAX_COMPONENTS - 1 {
                        deepest.types.push(TypeNode::VendorQualifier {
                            qualifier: 0,
                            inner,
                        });
                    }
                    assert_eq!(
                        deepest.validate_declarator_capabilities(
                            DeclaratorInvocation::StandaloneType(MAX_COMPONENTS - 1)
                        ),
                        Ok(())
                    );

                    let mut widest = parser_with_test_limits(b"", TestLimits::default());
                    widest.types.push(TypeNode::Int);
                    widest
                        .function_args
                        .try_reserve_exact(MAX_COMPONENTS - 3)
                        .expect("bounded adversarial argument arena");
                    widest
                        .function_args
                        .extend(std::iter::repeat_n(0, MAX_COMPONENTS - 3));
                    widest.types.push(TypeNode::Function {
                        return_type: 0,
                        arguments_start: 0,
                        arguments_end: MAX_COMPONENTS - 3,
                    });
                    assert_eq!(
                        widest.validate_declarator_capabilities(
                            DeclaratorInvocation::StandaloneType(1)
                        ),
                        Ok(())
                    );

                    let mut nested = parser_with_test_limits(b"", limits);
                    nested.types.push(TypeNode::Int);
                    nested.template_args.push(TemplateArgId::Type(0));
                    nested.type_name_components.push(Component {
                        bytes: b"name",
                        offset: 0,
                        template_args: Some((0, 1)),
                        destructor: false,
                        conversion: None,
                    });
                    nested.types.push(TypeNode::Named { start: 0, end: 1 });
                    let mut previous = 1;
                    for _ in 0..12 {
                        let argument_start = nested.template_args.len();
                        nested.template_args.push(TemplateArgId::Type(previous));
                        let qualifier = nested.type_name_components.len();
                        nested.type_name_components.push(Component {
                            bytes: b"vendor",
                            offset: 0,
                            template_args: Some((argument_start, argument_start + 1)),
                            destructor: false,
                            conversion: None,
                        });
                        nested.types.push(TypeNode::VendorQualifier {
                            qualifier,
                            inner: previous,
                        });
                        previous = nested.types.len() - 1;
                    }
                    assert!(matches!(
                        nested.validate_declarator_capabilities(
                            DeclaratorInvocation::StandaloneType(previous)
                        ),
                        Err(Failure::ComponentLimitExceeded {
                            attempted,
                            limit: MAX_COMPONENTS
                        }) if attempted == MAX_COMPONENTS + 1
                    ));

                    let mut corrupt = parser_with_test_limits(b"", TestLimits::default());
                    corrupt.types.push(TypeNode::Modified {
                        kind: super::Modifier::Pointer,
                        inner: 0,
                    });
                    assert!(matches!(
                        corrupt.validate_declarator_capabilities(
                            DeclaratorInvocation::StandaloneType(0)
                        ),
                        Err(Failure::InvalidFunctionName)
                    ));
                    let mut corrupt_member = parser_with_test_limits(b"", TestLimits::default());
                    corrupt_member.types.push(TypeNode::MemberPointer {
                        class: 0,
                        member: 0,
                    });
                    assert!(matches!(
                        corrupt_member.validate_declarator_capabilities(
                            DeclaratorInvocation::StandaloneType(0)
                        ),
                        Err(Failure::InvalidFunctionName)
                    ));
                    assert!(matches!(
                        corrupt_member.validate_declarator_capabilities(
                            DeclaratorInvocation::StandaloneType(1)
                        ),
                        Err(Failure::InvalidFunctionName)
                    ));
                })
                .expect("small-stack validator thread must start");
            child
                .join()
                .expect("iterative declarator validator must not abort");
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
    fn nested_and_template_depth_is_restored_after_every_error_class() {
        for input in [
            b"_ZN1a".as_slice(),
            b"_ZNE",
            b"_ZN1a1bE",
            b"_Z1fI",
            b"_Z1fIEv",
            b"_Z1fIqiE",
        ] {
            let limits = if input == b"_ZN1a1bE" {
                TestLimits {
                    components: 1,
                    ..TestLimits::default()
                }
            } else {
                TestLimits::default()
            };
            let mut parser = parser_with_test_limits(input, limits);
            assert!(parser.parse_mangled_name().is_err(), "input={input:?}");
            assert_eq!(parser.depth, limits.initial_depth, "input={input:?}");
        }
    }

    #[test]
    fn direct_templated_source_arena_push_accepts_exact_and_rejects_one_over() {
        let limits = TestLimits {
            components: 4,
            ..TestLimits::default()
        };
        let dummy = Component {
            bytes: b"D",
            offset: 0,
            template_args: None,
            destructor: false,
            conversion: None,
        };

        let mut exact = parser_with_test_limits(b"1XIiE", limits);
        exact.type_name_components.extend_from_slice(&[dummy; 3]);
        assert!(exact.parse_source_name_with_template_args(&[]).is_ok());
        assert_eq!(exact.type_name_components.len(), limits.components);

        let mut over = parser_with_test_limits(b"1XIiE", limits);
        over.type_name_components.extend_from_slice(&[dummy; 4]);
        assert!(matches!(
            over.parse_source_name_with_template_args(&[]),
            Err(Failure::ComponentLimitExceeded {
                attempted: 5,
                limit: 4
            })
        ));
        assert_eq!(over.type_name_components.len(), limits.components);
    }

    #[test]
    fn unsized_array_dimensions_match_bundled_parser() {
        assert_eq!(
            demangle(b"_Z1fA_i").expect("unsized array").name(),
            "f(int [])"
        );
        assert_eq!(
            demangle(b"_Z3fooA30_A_i")
                .expect("mixed sized and unsized array")
                .name(),
            "foo(int [30][])"
        );
        assert_eq!(
            demangle(b"_Z1fIA_iEvv")
                .expect("unsized array template argument")
                .name(),
            "void f<int []>()"
        );
        for raw in [b"_Z1fA".as_slice(), b"_Z1fAA_i"] {
            rejects(raw);
        }
    }

    #[test]
    fn malformed_template_and_array_boundaries_fail_closed() {
        for raw in [
            b"_Z1fI".as_slice(),
            b"_Z1fIi",
            b"_Z1fIiEv",
            b"_Z1fIiET",
            b"_Z1fIiET0",
            b"_Z1fIiET0_",
            b"_Z1fIiETZZZZZZZZZZZZZZZZZZZZ_",
            b"_Z1fIA4iEvv",
            b"_Z1fIA999999999999999999999999_iEvv",
            b"_Z1fIA4_Evv",
            b"_Z1fIIiEEvv",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn authoritative_depth_rows_require_seven_frames_exactly() {
        for raw in [
            b"_ZNSt13_Alloc_traitsISbIcSt18string_char_traitsIcEN5libcw5debug9_private_17allocator_adaptorIcSt24__default_alloc_templateILb0ELi327664EELb1EEEENS5_IS9_S7_Lb1EEEE15_S_instancelessE".as_slice(),
            b"_Z9hairyfuncM1YKFPVPFrPA2_PM1XKFKPA3_ilEPcEiE",
        ] {
            assert!(matches!(
                demangle_with_limits(
                    raw,
                    TestLimits {
                        depth: 6,
                        ..TestLimits::default()
                    }
                ),
                Err(Failure::NestingLimitExceeded {
                    attempted: 7,
                    limit: 6
                })
            ));
            let at_seven = demangle_with_limits(
                raw,
                TestLimits {
                    depth: 7,
                    ..TestLimits::default()
                },
            );
            let at_eight = demangle_with_limits(
                raw,
                TestLimits {
                    depth: 8,
                    ..TestLimits::default()
                },
            );
            assert!(at_seven.is_ok(), "raw={raw:?}, at_seven={at_seven:?}");
            assert!(at_eight.is_ok(), "raw={raw:?}, at_eight={at_eight:?}");
        }
    }

    #[test]
    fn local_source_markers_and_local_named_types_match_bundled_printer() {
        assert_eq!(
            demangle(b"_ZZN7myspaceL3foo_1EvEN11localstruct1fEZNS_3fooEvE16otherlocalstruct")
                .expect("local source marker and local named type")
                .name(),
            "myspace::foo()::localstruct::f(myspace::foo()::otherlocalstruct)"
        );
        rejects(b"_ZN1aLEv");
    }

    #[test]
    fn external_name_template_arguments_match_bundled_printer() {
        assert_eq!(
            demangle(b"_ZN13PatternDriver23StringScalarDeleteValueC1ERKNS_25ConflateStringScalarValueERKNS_25AbstractStringScalarValueERKNS_12TemplateEnumINS_12pdcomplementELZNS_16complement_namesEELZNS_14COMPLEMENTENUMEEEE")
                .expect("external-name template arguments")
                .name(),
            "PatternDriver::StringScalarDeleteValue::StringScalarDeleteValue(PatternDriver::ConflateStringScalarValue const&, PatternDriver::AbstractStringScalarValue const&, PatternDriver::TemplateEnum<PatternDriver::pdcomplement, PatternDriver::complement_names, PatternDriver::COMPLEMENTENUM> const&)"
        );
        rejects(b"_Z1fILZEEvv");
    }

    #[test]
    fn injected_complex_declarators_match_bundled_printer() {
        for (raw, expected) in [
            (b"_Z1fPFPA1_ivE".as_slice(), "f(int (*(*)()) [1])"),
            (
                b"_Z1fI1APS0_PKS0_EvT_T0_T1_PA4_S3_M1CS8_",
                "void f<A, A*, A const*>(A, A*, A const*, A const* (*) [4], A const* (* C::*) [4])",
            ),
            (
                b"_Z10hairyfunc5PFPFilEPcE",
                "hairyfunc5(int (*(*)(char*))(long))",
            ),
            (b"_ZNK1C1fIiEEPFivEv", "int (*C::f<int>() const)()"),
        ] {
            assert_eq!(demangle(raw).expect("complex declarator").name(), expected);
        }
    }

    #[test]
    fn cast_and_floating_expressions_match_bundled_printer() {
        for (raw, expected) in [
            (b"_Z1fILf1EEvv".as_slice(), "void f<(float)[1]>()"),
            (b"_Z1fILd1EEvv", "void f<(double)[1]>()"),
            (b"_Z1fILf1e2EEvv", "void f<(float)[1e2]>()"),
            (b"_Z1fILf1A2EEvv", "void f<(float)[1A2]>()"),
            (b"_Z1fILf1G2EEvv", "void f<(float)[1G2]>()"),
            (b"_Z1fILf1-2EEvv", "void f<(float)[1-2]>()"),
            (b"_Z1fILf1z2EEvv", "void f<(float)[1z2]>()"),
            (b"_Z1fILfn1EEvv", "void f<(float)-[1]>()"),
            (
                b"_Z1fILi1ELc120EEv1AIXplT_cviLd810000000000000000703DAD7A370C5EEE".as_slice(),
                "void f<1, (char)120>(A<(1)+((int)((double)[810000000000000000703DAD7A370C5]))>)",
            ),
            (
                b"_Z1fILi1EEv1AIXplT_cvingLf3f800000EEE",
                "void f<1>(A<(1)+((int)(-((float)[3f800000])))>)",
            ),
        ] {
            assert_eq!(
                demangle(raw).expect("cast/floating expression").name(),
                expected
            );
        }
        for raw in [
            b"_Z1fIXcvEEvv".as_slice(),
            b"_Z1fIXLf3f800000Evv",
            b"_Z1fILf1E2EEvv",
            b"_Z1fILf1\0Evv",
            b"_Z1fILfnEEvv",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn standard_template_substitution_as_nested_prefix_matches_bundled_printer() {
        assert_eq!(
            demangle(b"_ZNSbIcSt11char_traitsIcEN5libcw5debug27no_alloc_checking_allocatorEE12_S_constructIPcEES6_T_S7_RKS3_")
                .expect("standard template nested prefix")
                .name(),
            "char* std::basic_string<char, std::char_traits<char>, libcw::debug::no_alloc_checking_allocator>::_S_construct<char*>(char*, char*, libcw::debug::no_alloc_checking_allocator const&)"
        );
        rejects(b"_ZNSbI12_S_constructE");
    }

    #[test]
    fn sizeof_external_name_expression_matches_bundled_printer() {
        for (raw, expected) in [
            (b"_Z1fAszL_Z3foovE_i".as_slice(), "f(int [sizeof (foo())])"),
            (
                b"_Z1fAszL_ZZNK1N1A1fEvE3foo_0E_i",
                "f(int [sizeof (N::A::f() const::foo)])",
            ),
            (b"_Z1fAszL_ZZ1fIiEvvE1xE_i", "f(int [sizeof (f<int>()::x)])"),
        ] {
            assert_eq!(
                demangle(raw).expect("sizeof external name").name(),
                expected
            );
        }
        rejects(b"_Z1fAszL_Z3foov_i");
        rejects(b"_Z1fAsz_i");
    }

    #[test]
    fn legacy_cb_external_name_arguments_match_bundled_printer() {
        for (raw, expected) in [
            (b"2CBIL_Z3foocEE".as_slice(), "CB<foo(char)>"),
            (b"2CBIL_Z7IsEmptyEE", "CB<IsEmpty>"),
        ] {
            assert_eq!(
                demangle(raw).expect("external name expression").name(),
                expected
            );
        }
        rejects(b"2CBIL_Z3foocE");
    }

    #[test]
    fn indexed_nested_prefix_substitutions_match_bundled_printer() {
        for (raw, expected) in [
            (
                b"_ZGVN5libcw24_GLOBAL__N_cbll.cc0ZhUKa23compiler_bug_workaroundISt6vectorINS_13omanip_id_tctINS_5debug32memblk_types_manipulator_data_ctEEESaIS6_EEE3idsE".as_slice(),
                "guard variable for libcw::(anonymous namespace)::compiler_bug_workaround<std::vector<libcw::omanip_id_tct<libcw::debug::memblk_types_manipulator_data_ct>, std::allocator<libcw::omanip_id_tct<libcw::debug::memblk_types_manipulator_data_ct> > > >::ids",
            ),
            (
                b"_ZN5libcw5debug13cwprint_usingINS_9_private_12GlobalObjectEEENS0_17cwprint_using_tctIT_EERKS5_MS5_KFvRSt7ostreamE",
                "libcw::debug::cwprint_using_tct<libcw::_private_::GlobalObject> libcw::debug::cwprint_using<libcw::_private_::GlobalObject>(libcw::_private_::GlobalObject const&, void (libcw::_private_::GlobalObject::*)(std::ostream&) const)",
            ),
        ] {
            assert_eq!(
                demangle(raw).expect("indexed nested prefix").name(),
                expected,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn conversion_operators_match_bundled_printer() {
        for (raw, expected) in [
            (
                b"_ZN1AIfEcvT_IiEEv".as_slice(),
                "A<float>::operator int<int>()",
            ),
            (
                b"_ZNK5boost6spirit5matchI13rcs_deltatextEcvMNS0_4impl5dummyEFvvEEv",
                "boost::spirit::match<rcs_deltatext>::operator void (boost::spirit::impl::dummy::*)()() const",
            ),
        ] {
            assert_eq!(demangle(raw).expect("conversion operator").name(), expected);
        }
        for raw in [
            b"_ZN1A1fEcv".as_slice(),
            b"_ZN1A1fEcvi",
            b"_ZN1AIfEcvT0_IiEEv",
            b"_ZN1AIfEcvT_ILi1EEEv",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn recursive_local_function_entities_match_bundled_printer() {
        let last_depth = TestLimits {
            initial_depth: MAX_NESTING_DEPTH - 1,
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(b"_ZZ1fvE1x", last_depth)
                .expect("one local level at boundary")
                .name(),
            "f()::x"
        );
        assert!(
            demangle_with_limits(b"_ZZZ3BBdI3FooEvvENK3Fob3FabEvENK3Gob3GabEv", last_depth)
                .is_err()
        );
        assert_eq!(
            demangle(b"_ZZZ3BBdI3FooEvvENK3Fob3FabEvENK3Gob3GabEv")
                .expect("recursive local function entity")
                .name(),
            "BBd<Foo>()::Fob::Fab() const::Gob::Gab() const"
        );
        rejects(b"_ZZZ3BBdI3FooEvvENK3Fob3FabEvNK3Gob3GabEv");
        rejects(b"_ZZZ1fvE1xE1y");
    }

    #[test]
    fn local_function_entities_match_bundled_printer() {
        assert_eq!(
            demangle(b"_ZZ3BBdI3FooEvvENK3Fob3FabEv")
                .expect("local function entity")
                .name(),
            "BBd<Foo>()::Fob::Fab() const"
        );
        rejects(b"_ZZ3BBdI3FooEvvENK3Fob3FabEvv");
    }

    #[test]
    fn simple_local_names_match_bundled_printer() {
        for (raw, expected) in [
            (b"_ZZN1N1fEiE1p".as_slice(), "N::f(int)::p"),
            (b"_ZZN1N1fEiEs", "N::f(int)::string literal"),
            (b"_ZZL3foo_2vE4var1", "foo()::var1"),
            (b"_ZZL3foo_2vE4var1_0", "foo()::var1"),
        ] {
            assert_eq!(demangle(raw).expect("local name").name(), expected);
        }
        for raw in [b"_ZZN1N1fEi1p".as_slice(), b"_ZZN1N1fEiEs_"] {
            rejects(raw);
        }
    }

    #[test]
    fn expression_valued_array_dimensions_match_bundled_printer() {
        assert_eq!(
            demangle(b"_Z3fooILi2EEvRAplT_Li1E_i")
                .expect("expression-valued array dimension")
                .name(),
            "void foo<2>(int (&) [(2)+(1)])"
        );
        for raw in [b"_Z1fAplLi1E_i".as_slice(), b"_Z1fAplLi1ELi2Ei"] {
            rejects(raw);
        }
    }

    #[test]
    fn binary_template_expressions_match_bundled_printer() {
        assert_eq!(
            demangle(b"_Z1fIXLi1EEEvv")
                .expect("wrapped literal expression")
                .name(),
            "void f<1>()"
        );
        for (raw, expected) in [
            (
                b"_ZngILi42EEvN1AIXplT_Li2EEE1TE".as_slice(),
                "void operator-<42>(A<(42)+(2)>::T)",
            ),
            (
                b"_Z4dep9ILi3EEvP3fooIXgtT_Li2EEE",
                "void dep9<3>(foo<((3)>(2))>*)",
            ),
        ] {
            assert_eq!(demangle(raw).expect("binary expression").name(), expected);
        }
    }

    #[test]
    fn nested_operator_components_match_bundled_printer() {
        for (raw, expected) in [
            (
                b"_ZNKSt15_Deque_iteratorIP15memory_block_stRKS1_PS2_EeqERKS5_".as_slice(),
                "std::_Deque_iterator<memory_block_st*, memory_block_st* const&, memory_block_st* const*>::operator==(std::_Deque_iterator<memory_block_st*, memory_block_st* const&, memory_block_st* const*> const&) const",
            ),
            (
                b"_ZNKSt17__normal_iteratorIPK6optionSt6vectorIS0_SaIS0_EEEmiERKS6_",
                "std::__normal_iterator<option const*, std::vector<option, std::allocator<option> > >::operator-(std::__normal_iterator<option const*, std::vector<option, std::allocator<option> > > const&) const",
            ),
        ] {
            assert_eq!(demangle(raw).expect("nested operator").name(), expected);
        }
    }

    #[test]
    fn nested_type_template_arguments_prefer_the_active_function_template_scope() {
        assert_eq!(
            demangle(b"_ZStltI9file_pathSsEbRKSt4pairIT_T0_ES6_")
                .expect("authoritative std operator template")
                .name(),
            "bool std::operator< <file_path, std::string>(std::pair<file_path, std::string> const&, std::pair<file_path, std::string> const&)"
        );
    }

    #[test]
    fn operator_names_can_be_templated_and_std_qualified() {
        for (raw, expected) in [
            (b"_Zng".as_slice(), "operator-"),
            (b"_Zlt", "operator<"),
            (b"_ZltIiEvv", "void operator< <int>()"),
        ] {
            assert_eq!(demangle(raw).expect("operator name").name(), expected);
        }
        rejects(b"_ZngI");
    }

    #[test]
    fn operator_names_are_accepted_as_fully_consumed_data_encodings() {
        for (raw, expected) in [
            (b"_Zrm".as_slice(), "operator%"),
            (b"_Zpl", "operator+"),
            (b"_Zls", "operator<<"),
        ] {
            assert_eq!(
                demangle(raw).expect("operator data encoding").name(),
                expected
            );
        }
    }

    #[test]
    fn nested_name_substitutions_preserve_bundled_source_order() {
        for (raw, expected) in [
            (b"_ZN1A1fES_".as_slice(), "A::f(A)"),
            (b"_Z1fN1A1BES_", "f(A::B, A)"),
            (b"_Z1fN1A1BES0_", "f(A::B, A::B)"),
        ] {
            assert_eq!(demangle(raw).expect("nested substitution").name(), expected);
        }
    }

    #[test]
    fn unary_modifier_placement_matches_bundled_printer() {
        for (raw, expected) in [
            (b"_Z1fPi".as_slice(), "f(int*)"),
            (b"_Z1fPKi", "f(int const*)"),
            (b"_Z1fKPi", "f(int* const)"),
            (b"_Z1fRKVrPi", "f(int* restrict volatile const&)"),
        ] {
            assert_eq!(demangle(raw).expect("modifier oracle").name(), expected);
        }
    }

    #[test]
    fn reference_smashing_matches_bundled_printer_state_transitions() {
        for (raw, expected) in [
            (b"_Z1fRi".as_slice(), "f(int&)"),
            (b"_Z1fRRi", "f(int&)"),
            (b"_Z1fRRRi", "f(int&&)"),
            (b"_Z1fRRRRi", "f(int&&)"),
            (b"_Z1fRRRRRi", "f(int&&&)"),
            (b"_Z1fRRPi", "f(int*&)"),
            (b"_Z1fRRPRRi", "f(int&*&)"),
        ] {
            assert_eq!(
                demangle(raw).expect("reference-smashing oracle").name(),
                expected
            );
        }
    }

    #[test]
    fn contiguous_cv_qualifiers_use_bundled_pending_modifier_state() {
        for (raw, expected) in [
            (b"_Z1fKKi".as_slice(), "f(int const)"),
            (b"_Z1fVVKi", "f(int const volatile)"),
            (b"_Z1frrPi", "f(int* restrict)"),
            (b"_Z1fKVi", "f(int volatile const)"),
            (b"_Z1fVKi", "f(int const volatile)"),
            (b"_Z1fKVri", "f(int restrict volatile const)"),
            (b"_Z1frVKi", "f(int const volatile restrict)"),
            (b"_Z1fVKrKi", "f(int restrict const volatile)"),
            (b"_Z1fKVKVi", "f(int volatile const)"),
            (b"_Z1fKPKi", "f(int const* const)"),
            (b"_Z1fKVRKVi", "f(int volatile const& volatile const)"),
        ] {
            assert_eq!(
                demangle(raw).expect("CV pending-state oracle").name(),
                expected
            );
        }
    }

    #[test]
    fn malformed_substitutions_and_operator_codes_fail_closed() {
        for raw in [
            b"_Z1fS".as_slice(),
            b"_Z1fS0",
            b"_Z1fS-",
            b"_Z1fS!_",
            b"_Z1fS_",
            b"_Z1fSZZZZZZZZZZZZZZZZZZZZ_",
            b"_Zxx1X",
            b"_Zr",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn every_modifier_truncation_rejects_and_long_chain_is_iterative() {
        for raw in [b"_Z1fP".as_slice(), b"_Z1fR", b"_Z1fK", b"_Z1fV", b"_Z1fr"] {
            rejects(raw);
        }
        assert_eq!(
            demangle(b"_Z1fPPPPPPPPPPPPPPPi")
                .expect("15-pointer chain must not recurse")
                .name(),
            "f(int***************)"
        );
    }

    #[test]
    fn destructor_utf8_failure_does_not_mutate_output() {
        let parser = parser_with_test_limits(b"", TestLimits::default());
        let mut output = String::from("unchanged");
        let result = parser.push_component_text(
            &mut output,
            Component {
                bytes: b"\xff",
                offset: 7,
                template_args: None,
                destructor: true,
                conversion: None,
            },
        );
        assert!(matches!(result, Err(Failure::InvalidUtf8 { offset: 7 })));
        assert_eq!(output, "unchanged");
    }

    #[test]
    fn anonymous_namespace_identifiers_match_bundled_alias_rule() {
        for raw in [
            b"_Z10_GLOBAL__N".as_slice(),
            b"_Z10_GLOBAL_.N",
            b"_Z10_GLOBAL_$N",
        ] {
            assert_eq!(
                demangle(raw)
                    .expect("anonymous namespace identifier")
                    .name(),
                "(anonymous namespace)"
            );
        }
        assert_eq!(
            demangle(b"_Z10_GLOBAL__X")
                .expect("near miss remains literal")
                .name(),
            "_GLOBAL__X"
        );
        assert_eq!(
            demangle(b"_Z9_GLOBAL_N")
                .expect("short near miss remains literal")
                .name(),
            "_GLOBAL_N"
        );
    }

    #[test]
    fn guard_variable_special_name_uses_the_normal_name_parser() {
        assert_eq!(
            demangle(b"_ZGV1x").expect("guard variable").name(),
            "guard variable for x"
        );
        for raw in [b"_ZGV".as_slice(), b"_ZGV1", b"_ZGV1xjunk"] {
            rejects(raw);
        }
    }

    #[test]
    fn template_template_parameter_application_matches_bundled_parser() {
        assert_eq!(
            demangle(b"_Z4makeI7FactoryiET_IT0_Ev")
                .expect("template-template application")
                .name(),
            "Factory<int> make<Factory, int>()"
        );
        assert_eq!(
            demangle(b"SaIiE")
                .expect("allocator template substitution")
                .name(),
            "std::allocator<int>"
        );
        assert_eq!(
            demangle(b"SbIcE")
                .expect("basic_string template substitution")
                .name(),
            "std::basic_string<char>"
        );
        for raw in [
            b"_Z4makeI7FactoryiET_I".as_slice(),
            b"_Z4makeI7FactoryiET_IEv",
            b"iIiE",
            b"SsIiE",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn constructor_and_destructor_names_use_the_structural_owner() {
        for (raw, expected) in [
            (b"_ZN1AC1Ev".as_slice(), "A::A()"),
            (b"_ZN1AD1Ev", "A::~A()"),
            (
                b"_ZNSdD0Ev",
                "std::basic_iostream<char, std::char_traits<char> >::~basic_iostream()",
            ),
        ] {
            assert_eq!(
                demangle(raw).expect("constructor/destructor name").name(),
                expected
            );
        }
        for raw in [
            b"_ZNC1Ev".as_slice(),
            b"_ZN1AC0Ev",
            b"_ZN1AD3Ev",
            b"_ZNSdDEv",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn global_constructor_and_destructor_wrappers_match_bundled_parser() {
        for (raw, expected) in [
            (
                b"_GLOBAL__I__Z2fnv".as_slice(),
                "global constructors keyed to fn()",
            ),
            (b"_GLOBAL_.I__Z2fnv", "global constructors keyed to fn()"),
            (b"_GLOBAL_$D_key", "global destructors keyed to key"),
        ] {
            assert_eq!(
                demangle(raw).expect("global keyed wrapper").name(),
                expected
            );
        }
        for raw in [
            b"_GLOBAL_".as_slice(),
            b"_GLOBAL__I",
            b"_GLOBAL__X_key",
            b"_GLOBAL_XI_key",
            b"_GLOBAL__I_",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn local_source_name_discriminators_match_bundled_parser() {
        assert_eq!(
            demangle(b"_ZL3foo_2")
                .expect("single-underscore discriminator")
                .name(),
            "foo"
        );
        assert_eq!(
            demangle(b"_ZL3foo__10_")
                .expect("double-underscore discriminator")
                .name(),
            "foo"
        );
        for raw in [
            b"_ZL".as_slice(),
            b"_ZL3foo_",
            b"_ZL3foo__",
            b"_ZL3foo__10",
            b"_ZL3foo_n1",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn source_lengths_follow_bundled_number_rules() {
        assert_eq!(
            demangle(b"_Z01f").expect("leading zero is accepted").name(),
            "f"
        );
        rejects(b"_Z0");
        rejects(b"_Z00");
        assert!(matches!(
            demangle(b"_Z999999999999999999999999999999x"),
            Err(Failure::NumberOverflow { .. })
        ));
        assert!(matches!(
            demangle(b"_Z9short"),
            Err(Failure::SourceNamePastEnd { .. })
        ));
    }

    #[test]
    fn every_required_prefix_and_nested_boundary_rejects_truncation() {
        for input in [
            b"".as_slice(),
            b"_",
            b"_Z",
            b"_ZN",
            b"_ZNK",
            b"_ZN1",
            b"_ZN1N",
            b"_ZN1N1",
            b"_ZN1N1f",
        ] {
            rejects(input);
        }
        rejects(b"Z1f");
        rejects(b"__Z1f");
        rejects(b"_ZN1N1f");
        rejects(b"_ZNE");
        rejects(b"_ZNKE");
    }

    #[test]
    fn standalone_builtins_standard_vendor_and_typeinfo_match_oracle() {
        for (raw, expected) in [
            (b"v".as_slice(), "void"),
            (b"w", "wchar_t"),
            (b"b", "bool"),
            (b"a", "signed char"),
            (b"h", "unsigned char"),
            (b"s", "short"),
            (b"t", "unsigned short"),
            (b"j", "unsigned int"),
            (b"l", "long"),
            (b"m", "unsigned long"),
            (b"x", "long long"),
            (b"y", "unsigned long long"),
            (b"n", "__int128"),
            (b"o", "unsigned __int128"),
            (b"f", "float"),
            (b"d", "double"),
            (b"e", "long double"),
            (b"g", "__float128"),
            (b"z", "..."),
            (b"St9bad_alloc", "std::bad_alloc"),
            (b"U4_farrVKPi", "int* const volatile restrict _far"),
            (b"_ZTI7a_class", "typeinfo for a_class"),
        ] {
            let actual = demangle(raw).expect("approved standalone GNU type row");
            assert_eq!(actual.full_name(), expected, "raw={raw:?}");
            assert_eq!(actual.name(), expected, "selector must start at byte zero");
        }
    }

    #[test]
    fn templated_vendor_qualifiers_render_and_substitute_as_complete_types() {
        for (raw, expected) in [
            (b"U1xIiEi".as_slice(), "int x<int>"),
            (b"_Z1fU1xIiEiS_", "f(int x<int>, int x<int>)"),
            (b"U1xI1YIiT_EEi", "int x<Y<int, int> >"),
            (
                b"_Z1fU1xI1YIiEEiS_S0_S1_",
                "f(int x<Y<int> >, Y, Y<int>, int x<Y<int> >)",
            ),
        ] {
            assert_eq!(
                demangle(raw).expect("templated vendor qualifier").name(),
                expected,
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn templated_vendor_qualifier_errors_restore_scope_and_fail_closed() {
        for raw in [
            b"U1xI".as_slice(),
            b"U1xIi",
            b"U1xIEi",
            b"U1xIiEEi",
            b"U1xIiEii",
        ] {
            rejects(raw);
        }

        let mut parser = parser_with_test_limits(b"U1xI1YIiT_E", TestLimits::default());
        assert!(parser.parse_vendor_qualified_type().is_err());
        assert!(parser.in_progress_template_scopes.is_empty());
        assert_eq!(parser.depth, 0);
    }

    #[test]
    fn templated_vendor_qualifiers_enforce_components_backreferences_utf8_and_budgets() {
        let expected = "int x<int>";
        let exact = TestLimits {
            output: expected.len(),
            budget: expected.len(),
            components: 4,
            backreferences: 1,
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(b"U1xIiEi", exact)
                .expect("exact templated vendor limits")
                .name(),
            expected
        );
        assert!(matches!(
            demangle_with_limits(
                b"U1xIiEi",
                TestLimits {
                    components: 3,
                    ..exact
                }
            ),
            Err(Failure::ComponentLimitExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"U1xIiEi",
                TestLimits {
                    backreferences: 0,
                    ..exact
                }
            ),
            Err(Failure::BackreferenceLimitExceeded {
                attempted: 1,
                limit: 0
            })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"U1xIiEi",
                TestLimits {
                    output: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::OutputLimitExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"U1xIiEi",
                TestLimits {
                    budget: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::BudgetExceeded { .. })
        ));

        let depth_exact = TestLimits {
            initial_depth: MAX_NESTING_DEPTH - 2,
            ..TestLimits::default()
        };
        assert!(demangle_with_limits(b"U1xIiEi", depth_exact).is_ok());
        let depth_over = TestLimits {
            initial_depth: MAX_NESTING_DEPTH - 1,
            ..TestLimits::default()
        };
        assert!(matches!(
            demangle_with_limits(b"U1xIiEi", depth_over),
            Err(Failure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH
            }) if attempted == MAX_NESTING_DEPTH + 1
        ));
        assert!(matches!(
            demangle(b"U1\xffIiEi"),
            Err(Failure::InvalidUtf8 { offset: 2 })
        ));
    }

    #[test]
    fn vendor_qualifiers_preserve_substitutions_depth_and_budgets() {
        assert_eq!(
            demangle(b"_Z1fU4_fariS_")
                .expect("vendor-qualified substitution")
                .name(),
            "f(int _far, int _far)"
        );

        let mut exact_depth = Vec::new();
        for _ in 0..MAX_NESTING_DEPTH {
            exact_depth.extend_from_slice(b"U1x");
        }
        exact_depth.push(b'i');
        assert!(demangle(&exact_depth).is_ok());
        exact_depth.splice(0..0, b"U1x".iter().copied());
        assert!(matches!(
            demangle(&exact_depth),
            Err(Failure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH
            }) if attempted == MAX_NESTING_DEPTH + 1
        ));

        let expected = "int* const volatile restrict _far";
        let exact = TestLimits {
            output: expected.len(),
            budget: expected.len(),
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(b"U4_farrVKPi", exact)
                .expect("exact standalone type budgets")
                .name(),
            expected
        );
        assert!(matches!(
            demangle_with_limits(
                b"U4_farrVKPi",
                TestLimits {
                    output: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::OutputLimitExceeded { .. })
        ));
        assert!(matches!(
            demangle_with_limits(
                b"U4_farrVKPi",
                TestLimits {
                    budget: expected.len() - 1,
                    ..exact
                }
            ),
            Err(Failure::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn standalone_and_typeinfo_malformed_boundaries_fail_closed() {
        for raw in [
            b"".as_slice(),
            b"iX",
            b"St",
            b"St0bad_alloc",
            b"St9bad_allo",
            b"U",
            b"U4_far",
            b"U9_fari",
            b"U1\xffi",
            b"_ZTI",
            b"_ZTI7a_classX",
            b"_ZTV7a_class",
            b"_ZTS7a_class",
        ] {
            rejects(raw);
        }
    }

    #[test]
    fn unsupported_and_trailing_types_fail_closed() {
        assert!(matches!(
            demangle(b"_Z1fq"),
            Err(Failure::UnsupportedType {
                offset: 4,
                found: b'q'
            })
        ));
        assert!(matches!(
            demangle(b"_Z1fiq"),
            Err(Failure::UnsupportedType {
                offset: 5,
                found: b'q'
            })
        ));
        rejects(b"_Z1fvi");
        rejects(b"_Z1fiv");
        rejects(b"_Z1fvjunk");
        rejects(b"_Z1fi.clone");
    }

    #[test]
    fn invalid_utf8_is_rejected_without_partial_result() {
        assert!(matches!(
            demangle(b"_Z1\xff"),
            Err(Failure::InvalidUtf8 { .. })
        ));
        assert!(matches!(
            demangle(b"_Z2\xc3x"),
            Err(Failure::InvalidUtf8 { .. })
        ));
        assert_eq!(
            demangle("_Z2é".as_bytes()).expect("valid UTF-8").name(),
            "é"
        );
    }

    #[test]
    fn input_limit_accepts_exact_and_rejects_one_over() {
        let exact_identifier_len = MAX_INPUT_BYTES - 7;
        let mut exact = String::from("_Z65529");
        exact.push_str(&"x".repeat(exact_identifier_len));
        assert_eq!(exact.len(), MAX_INPUT_BYTES);
        assert!(demangle(exact.as_bytes()).is_ok());

        let mut over = exact.into_bytes();
        over.push(b'x');
        assert!(matches!(
            demangle(&over),
            Err(Failure::InputLimitExceeded { attempted, limit })
                if attempted == MAX_INPUT_BYTES + 1 && limit == MAX_INPUT_BYTES
        ));
    }

    #[test]
    fn output_and_attempt_budget_accept_exact_and_reject_one_under() {
        let raw = b"_ZN3abc3defEic";
        let expected = "abc::def(int, char)";
        let exact = TestLimits {
            output: expected.len(),
            budget: expected.len(),
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(raw, exact)
                .expect("exact limits")
                .name(),
            expected
        );

        let output_short = TestLimits {
            output: expected.len() - 1,
            ..exact
        };
        assert!(matches!(
            demangle_with_limits(raw, output_short),
            Err(Failure::OutputLimitExceeded { .. })
        ));
        let budget_short = TestLimits {
            budget: expected.len() - 1,
            ..exact
        };
        assert!(matches!(
            demangle_with_limits(raw, budget_short),
            Err(Failure::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn component_limit_accepts_exact_and_rejects_one_over() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"_ZN");
        for _ in 0..MAX_COMPONENTS {
            raw.extend_from_slice(b"1a");
        }
        raw.push(b'E');
        assert!(demangle(&raw).is_ok());

        let _ = raw.pop();
        raw.extend_from_slice(b"1aE");
        assert!(matches!(
            demangle(&raw),
            Err(Failure::ComponentLimitExceeded {
                attempted,
                limit: MAX_COMPONENTS
            }) if attempted == MAX_COMPONENTS + 1
        ));
    }

    #[test]
    fn backreference_limit_accepts_exact_and_rejects_next_candidate() {
        let exact = TestLimits {
            backreferences: 1,
            ..TestLimits::default()
        };
        assert_eq!(
            demangle_with_limits(b"_Z1f1X", exact)
                .expect("one named type creates one candidate")
                .name(),
            "f(X)"
        );
        assert!(matches!(
            demangle_with_limits(b"_Z1fP1X", exact),
            Err(Failure::BackreferenceLimitExceeded {
                attempted: 2,
                limit: 1
            })
        ));
    }

    #[test]
    fn depth_limit_accepts_exact_and_rejects_one_over() {
        let exact = TestLimits {
            initial_depth: MAX_NESTING_DEPTH - 1,
            ..TestLimits::default()
        };
        assert!(demangle_with_limits(b"_ZN1a1bE", exact).is_ok());
        let over = TestLimits {
            initial_depth: MAX_NESTING_DEPTH,
            ..TestLimits::default()
        };
        assert!(matches!(
            demangle_with_limits(b"_ZN1a1bE", over),
            Err(Failure::NestingLimitExceeded {
                attempted,
                limit: MAX_NESTING_DEPTH
            }) if attempted == MAX_NESTING_DEPTH + 1
        ));
    }

    #[test]
    fn repeated_malformed_input_does_not_panic_or_amplify_allocations() {
        for length in 0..=256 {
            let input = vec![b'9'; length];
            for _ in 0..32 {
                rejects(&input);
            }
        }
    }
}
