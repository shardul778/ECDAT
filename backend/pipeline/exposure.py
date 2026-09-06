import os
import ast
import re
from typing import Optional, Set, Tuple, Dict, List

CRITICAL_PATH_PATTERN = re.compile(r"(auth|login|payments?|tokens?)", re.IGNORECASE)
TEST_PATH_PATTERN = re.compile(r"(^|[/\\])(tests?|mock|mocks|conftest|fixtures?)([/\\]|$)|test_|_test\.py$", re.IGNORECASE)
ROUTE_DECORATOR_PATTERN = re.compile(r"(app|router|api)\.(route|post|get|put|delete|patch)", re.IGNORECASE)

class ModuleCallGraphVisitor(ast.NodeVisitor):
    def __init__(self):
        self.functions: Dict[str, Dict] = {}
        self.current_func: Optional[str] = None

    def _decorator_name(self, dec_node: ast.AST) -> Optional[str]:
        call_or_attr = dec_node
        args_repr = ""
        if isinstance(dec_node, ast.Call):
            call_or_attr = dec_node.func
            if dec_node.args and isinstance(dec_node.args[0], ast.Constant):
                args_repr = f"('{dec_node.args[0].value}')"
            
        parts = []
        curr = call_or_attr
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            
        dec_name = ".".join(reversed(parts))
        if ROUTE_DECORATOR_PATTERN.search(dec_name):
            return f"@{dec_name}{args_repr}"
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self.current_func
        func_name = node.name
        self.current_func = func_name
        
        start_line = node.lineno
        end_line = getattr(node, "end_lineno", start_line + 50)
        
        route_decorator = None
        for dec in node.decorator_list:
            matched_dec = self._decorator_name(dec)
            if matched_dec:
                route_decorator = matched_dec
                break
                
        self.functions[func_name] = {
            "start": start_line,
            "end": end_line,
            "is_route": route_decorator is not None,
            "decorator": route_decorator,
            "callees": set()
        }
        
        self.generic_visit(node)
        self.current_func = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev_func = self.current_func
        func_name = node.name
        self.current_func = func_name
        
        start_line = node.lineno
        end_line = getattr(node, "end_lineno", start_line + 50)
        
        route_decorator = None
        for dec in node.decorator_list:
            matched_dec = self._decorator_name(dec)
            if matched_dec:
                route_decorator = matched_dec
                break
                
        self.functions[func_name] = {
            "start": start_line,
            "end": end_line,
            "is_route": route_decorator is not None,
            "decorator": route_decorator,
            "callees": set()
        }
        
        self.generic_visit(node)
        self.current_func = prev_func

    def visit_Call(self, node: ast.Call):
        if self.current_func and isinstance(node.func, ast.Name):
            callee = node.func.id
            if self.current_func in self.functions:
                self.functions[self.current_func]["callees"].add(callee)
        self.generic_visit(node)

def tag_exposure(
    file_path: str,
    line_number: int,
    base_dir: Optional[str] = None,
    confidence: Optional[str] = None
) -> Tuple[str, str]:
    """
    Tags exposure level and provides an explainable reason:
    1. Test directory precedence -> 'Test-only'
    2. Path keywords (auth, login, payment, token) -> 'Critical'
    3. Direct route decorator -> 'Externally Exposed'
    4. Indirect route call -> 'Externally Exposed'
    5. Default -> 'Internal-only'
    """
    normalized_path = file_path.replace("\\", "/")
    
    # 1. Test directory precedence -> Test-only
    if TEST_PATH_PATTERN.search(normalized_path):
        if confidence == "Medium (Single-Engine)":
            reason = "Found in test file by one engine only — downweighted due to test context and partial detection"
        else:
            reason = "Found in test file — both engines agree, but downweighted due to test context"
        return ("Test-only", reason)

    # 2. Critical path check
    match = CRITICAL_PATH_PATTERN.search(normalized_path)
    if match:
        keyword = match.group(1).lower()
        return ("Critical", f"File path contains critical security keyword '{keyword}/'")

    # 3. Check AST for direct or indirect route exposure
    full_path = os.path.join(base_dir, file_path) if base_dir else file_path
    if os.path.exists(full_path) and full_path.endswith(".py"):
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=full_path)
            visitor = ModuleCallGraphVisitor()
            visitor.visit(tree)
            
            # Check direct enclosure in route function
            for func_name, info in visitor.functions.items():
                if info["start"] <= line_number <= info["end"]:
                    if info["is_route"]:
                        dec_str = info["decorator"] or "@app.route"
                        return ("Externally Exposed", f"Directly enclosed in route handler '{func_name}' ({dec_str})")
                    
                    # Check if this function is called by a route function (Indirect Exposure)
                    for caller_name, caller_info in visitor.functions.items():
                        if caller_info["is_route"] and func_name in caller_info["callees"]:
                            caller_dec = caller_info["decorator"] or "@app.route"
                            return ("Externally Exposed", f"Indirectly called by route '{caller_name}' ({caller_dec})")
        except Exception:
            pass

    # 4. Default internal-only
    return ("Internal-only", "Internal module with no external route exposure or auth path keywords")
