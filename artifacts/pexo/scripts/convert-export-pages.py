from html.parser import HTMLParser
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
PAGES = {
    "PexlyHomepage": "pexly-home-routed.html",
    "PhysicalProductsExport": "physical-products-source.html",
    "GiftCardsExport": "gift-cards-source.html",
    "AboutUsExport": "about-us.html",
    "TeamsExport": "teams.html",
    "CareerExport": "career.html",
    "BlogsExport": "blogs.html",
}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
ATTRS = {
    "class": "className", "for": "htmlFor", "tabindex": "tabIndex",
    "readonly": "readOnly", "maxlength": "maxLength", "colspan": "colSpan",
    "rowspan": "rowSpan", "contenteditable": "contentEditable",
    "crossorigin": "crossOrigin", "srcset": "srcSet", "usemap": "useMap",
    "frameborder": "frameBorder", "allowfullscreen": "allowFullScreen",
    "autocomplete": "autoComplete", "autofocus": "autoFocus",
    "formaction": "formAction", "formenctype": "formEncType",
    "formmethod": "formMethod", "formnovalidate": "formNoValidate",
    "formtarget": "formTarget", "http-equiv": "httpEquiv",
    "accept-charset": "acceptCharset", "datetime": "dateTime",
    "playsinline": "playsInline", "srcdoc": "srcDoc",
    "xlink:href": "xlinkHref", "xmlns:xlink": "xmlnsXlink",
    "stroke-width": "strokeWidth", "stroke-linecap": "strokeLinecap",
    "stroke-linejoin": "strokeLinejoin", "fill-rule": "fillRule",
    "clip-rule": "clipRule", "fill-opacity": "fillOpacity",
    "stroke-opacity": "strokeOpacity", "stroke-dasharray": "strokeDasharray",
    "stroke-dashoffset": "strokeDashoffset", "font-family": "fontFamily",
    "font-size": "fontSize", "text-anchor": "textAnchor",
    "dominant-baseline": "dominantBaseline", "stop-color": "stopColor",
    "stop-opacity": "stopOpacity", "vector-effect": "vectorEffect",
    "preserveaspectratio": "preserveAspectRatio", "viewbox": "viewBox",
    "maskunits": "maskUnits", "maskcontentunits": "maskContentUnits",
    "gradientunits": "gradientUnits", "gradienttransform": "gradientTransform",
}
BOOL = {"allowfullscreen", "async", "autofocus", "autoplay", "checked", "controls", "default", "defer", "disabled", "formnovalidate", "hidden", "loop", "multiple", "muted", "nomodule", "novalidate", "open", "playsinline", "readonly", "required", "reversed", "selected"}


class Node:
    def __init__(self, tag=None, attrs=None, text=None):
        self.tag, self.attrs, self.text = tag, attrs or [], text
        self.children = []


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.stack = [self.root]
        self.body = False
        self.in_head = False
        self.in_style = False
        self.css = []
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = [(k, v) for k, v in attrs if k not in {"integrity", "crossorigin"}]
        if tag == "style":
            self.in_style = True
            self.css.append("")
            return
        if tag == "head":
            self.in_head = True
            return
        if tag == "body":
            self.body = True
            return
        if tag == "script":
            self.skip_depth += 1
            return
        if not self.body or self.skip_depth:
            return
        node = Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.body and not self.skip_depth:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == "style":
            self.in_style = False
            return
        if tag == "head":
            self.in_head = False
            return
        if tag == "body":
            self.body = False
            return
        if tag == "script":
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if not self.body or self.skip_depth:
            return
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.in_style:
            self.css[-1] += data
            return
        if not self.body or self.skip_depth or not data:
            return
        self.stack[-1].children.append(Node(text=data))


def get_attr(node, name, default=""):
    for key, value in node.attrs:
        if key == name:
            return value or ""
    return default


def classes(node):
    return get_attr(node, "class").split()


def text_content(node):
    if node.text is not None:
        return node.text
    return "".join(text_content(child) for child in node.children)


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def camel_style(value):
    pairs = []
    for declaration in value.split(";"):
        if ":" not in declaration:
            continue
        key, val = declaration.split(":", 1)
        key, val = key.strip(), val.strip()
        if not key or not val:
            continue
        prop = key if key.startswith("--") else re.sub(r"-([a-z])", lambda m: m.group(1).upper(), key)
        pairs.append(f"{json.dumps(prop)}: {json.dumps(val)}")
    return "{{" + ", ".join(pairs) + "}}"


ASSET_INDEX = 0
ASSET_SCOPE = ""
row_titles = {}
def attrs_jsx(node):
    global ASSET_INDEX
    result = []
    for key, value in node.attrs:
        if value is None:
            value = True
        if key == "style":
            result.append("style=" + camel_style(str(value))[:-1] + " as any}")
            continue
        name = ATTRS.get(key, key)
        if key.lower() in BOOL:
            result.append(f"{name}={{{str(bool(value)).lower()}}}")
        elif key == "src" and str(value).startswith("data:image/"):
            match = re.match(r"data:image/([^;,]+);base64,", str(value))
            ext = (match.group(1).split("+")[0] if match else "png").replace("jpeg", "jpg")
            ASSET_INDEX += 1
            asset = f"/export-assets/inline-{ASSET_SCOPE}-{ASSET_INDEX}.{ext}"
            # The asset is emitted after parsing by a second pass; keeping the original
            # source in an attribute would needlessly bloat the React bundle.
            inline_assets[asset] = str(value)
            result.append(f"src={{{json.dumps(asset)}}}")
        elif isinstance(value, bool):
            result.append(f"{name}={{{str(value).lower()}}}")
        elif key in {"maxlength", "minlength", "tabindex", "rowspan", "colspan"} and re.fullmatch(r"[+-]?\d+", str(value)):
            result.append(f"{name}={{{int(value)}}}")
        elif key in {"width", "height", "x", "y", "cx", "cy", "r", "rx", "ry", "stroke-width"}:
            if re.fullmatch(r"-?\d+(?:\.\d+)?", str(value)):
                result.append(f"{name}={{{value}}}")
            else:
                result.append(f"{name}={{{json.dumps(str(value))} as any}}")
        else:
            result.append(f"{name}={{{json.dumps(str(value), ensure_ascii=False)}}}")
    return (" " + " ".join(result)) if result else ""


def stringify(node, page_name):
    if node.text is not None:
        return "{" + json.dumps(node.text, ensure_ascii=False) + "}"
    # Replace page-controlled catalog containers with live React components.
    if page_name == "PhysicalProductsExport" and node.tag == "div" and "sp-row" in classes(node):
        row_id = get_attr(node, "id")
        parent_title = row_titles.get(id(node))
        if not parent_title:
            parent_title = get_attr(node, "data-live-section")
        if parent_title:
            cls = get_attr(node, "class")
            props = f' sectionTitle={{{json.dumps(parent_title)}}} rowId={{{json.dumps(row_id)}}} rowClass={{{json.dumps(cls)}}}'
            return f"<ShopifyLiveRow{props} />"
    if page_name == "GiftCardsExport" and node.tag == "div" and get_attr(node, "id") == "g-shelf":
        return "<LiveGiftCatalog />"
    if page_name == "GiftCardsExport" and node.tag == "div" and "g-search" in classes(node):
        return "<GiftHeaderSearch />"
    if page_name == "GiftCardsExport" and node.tag == "select" and get_attr(node, "id") == "g-country":
        return "<GiftCountrySelect />"
    if page_name == "GiftCardsExport" and node.tag == "button" and "g-cart" in classes(node):
        return "<GiftCartButton />"

    name = node.tag
    attrs = attrs_jsx(node)
    if name in VOID:
        return f"<{name}{attrs} />"
    children = "".join(stringify(child, page_name) for child in node.children)
    return f"<{name}{attrs}>{children}</{name}>"


def section_titles(root):
    found = {}
    for sec in walk(root):
        if sec.tag not in {"section", "div"} or "sp-sec" not in classes(sec):
            continue
        title = next((text_content(n).strip() for n in walk(sec) if "sp-h" in classes(n)), "")
        for row in walk(sec):
            if row.tag == "div" and "sp-row" in classes(row) and any("sp-card" in classes(c) for c in row.children):
                normalized = title.strip().lower()
                if normalized in {"hot right now", "our top picks", "everyday finds under $25", "picked just for you"}:
                    found[id(row)] = title
    return found


inline_assets = {}
all_css = []
converted = {}

for component, file_name in PAGES.items():
    ASSET_INDEX = 0
    ASSET_SCOPE = component
    inline_assets = {}
    parser = PageParser()
    parser.feed((PUBLIC / file_name).read_text(errors="ignore"))
    root = parser.root
    all_css.extend(parser.css)
    row_titles = section_titles(root) if component == "PhysicalProductsExport" else {}
    body = "".join(stringify(child, component) for child in root.children)
    converted[component] = body
    for path, data_uri in inline_assets.items():
        mime_data = re.match(r"data:[^,]+;base64,(.*)", data_uri, re.S)
        if mime_data:
            import base64
            out = ROOT / "public" / path.lstrip("/")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(base64.b64decode(mime_data.group(1)))

# Preserve one shared stylesheet, deduplicating Webflow's repeated global bundles.
unique_css = []
seen = set()
for css in all_css:
    css = css.strip()
    if css and css not in seen:
        seen.add(css)
        unique_css.append(css)
css_text = "\n\n".join(unique_css)
# The source exports carry Webflow's no-JavaScript transition start states. Native
# markup has no Webflow runtime, so remove the transient hidden/offset rules.
css_text = re.sub(r"(?:html\.)?w-mod-js:not\(\.w-mod-ix\)\s+\[data-w-id=[^\]]+\]\s*\{[^}]*\}", "", css_text)
css_text += "\n\n/* Exported pages render as native React; reveal Webflow's staged content without its runtime. */\nhtml, body { min-height: 100%; }\n"
(ROOT / "scripts" / ".export-source-styles.css").write_text(css_text)

out = [
    'import { ShopifyLiveRow } from "@/components/marketing/shopify-live-row";',
    'import { GiftCartButton, GiftCountrySelect, GiftExportProvider, GiftHeaderSearch, LiveGiftCatalog } from "@/components/marketing/live-gift-catalog";',
    'import { ExportPageShell } from "@/components/marketing/export-page-shell";',
    "",
]
for component, markup in converted.items():
    out.append(f"export function {component}() {{")
    out.append("  return (")
    out.append(f'    <ExportPageShell pageName="{component}">')
    if component == "GiftCardsExport":
        out.append("      <GiftExportProvider>")
    out.append("        " + markup)
    if component == "GiftCardsExport":
        out.append("      </GiftExportProvider>")
    out.append("    </ExportPageShell>")
    out.append("  );")
    out.append("}")
    out.append("")
(ROOT / "src" / "pages" / "export-pages.tsx").write_text("\n".join(out))
print("Generated native React exports:", ", ".join(converted))
print("Global CSS bytes:", len(css_text.encode()))
print("React source bytes:", len(("\n".join(out)).encode()))
