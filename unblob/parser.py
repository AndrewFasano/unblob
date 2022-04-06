import itertools

from lark import Lark, Transformer, UnexpectedCharacters

_hex_string_parser = Lark(
    """
    %import common.HEXDIGIT
    %import common.NUMBER
    %import common.NEWLINE
    %import common.WS
    %ignore WS

    COMMENT:  "//" /(.)+/ NEWLINE?

    %ignore COMMENT

    start: item+

    item: LITERAL           -> literal
        | WILDCARD          -> wildcard
        | FIRSTNIBLE        -> first_nible
        | SECONDNIBLE       -> second_nible
        | JUMP              -> jump
        | RANGE_JUMP        -> range_jump
        | alternative

    alternative: "(" item+ (ALTERNATIVE_SEPARATOR item+)+ ")"
    ALTERNATIVE_SEPARATOR: "|"
    LITERAL: HEXDIGIT HEXDIGIT
    WILDCARD: "??"
    FIRSTNIBLE: "?" HEXDIGIT
    SECONDNIBLE: HEXDIGIT "?"
    JUMP: "[" NUMBER "]"
    RANGE_JUMP: "[" NUMBER "-" NUMBER "]"
"""
)


class _HexStringToRegex(Transformer):
    def literal(self, s):
        return f"\\x{s[0]}"

    def wildcard(self, _s):
        return "."

    def first_nible(self, s):
        second_nible = s[0][1]
        byte_list = ",".join(
            [f"\\x{first_nible:x}{second_nible}" for first_nible in range(16)]
        )
        return f"[{byte_list}]"

    def second_nible(self, s):
        first_nible = s[0][0]
        return f"[\\x{first_nible}0-\\x{first_nible}f]"

    def jump(self, s):
        jump_length = s[0][1:-1]
        return f".{{{jump_length}}}"

    def range_jump(self, s):
        jumps = s[0][1:-1].split("-", 1)
        return f".{{{jumps[0]},{jumps[1]}}}"

    def alternative(self, s):
        spl = [
            "".join(body)
            for x, body in itertools.groupby(s, lambda item: item == "|")
            if not x
        ]
        alternatives = "|".join(spl)
        return f"({alternatives})"

    def item(self, s):
        return s[0]

    def start(self, s):
        return "".join(s).encode()


def hexstring2regex(hexastr):
    try:
        parsed = _hex_string_parser.parse(hexastr)
    except UnexpectedCharacters as e:
        raise ValueError(str(e)) from e
    regex = _HexStringToRegex().transform(parsed)
    return regex
