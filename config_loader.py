def load_config_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        with open(path, "r", encoding="shift_jis", errors="ignore") as f:
            lines = f.readlines()

    lines = [ln.rstrip("\n") for ln in lines]

    return lines


# ============================================================
# VDOMごとにコンフィグを分割
# ============================================================

def split_vdoms(lines):
    vdoms = {}
    current_vdom = None
    collecting = False
    buffer = []

    for ln in lines:
        ln = ln.strip()

        if ln.startswith("config vdom"):
            collecting = True
            continue

        if collecting and ln.startswith("edit"):
            # 新しいVDOM開始
            if current_vdom and buffer:
                vdoms[current_vdom] = buffer.copy()

            current_vdom = ln.replace("edit", "").strip().replace('"', "")
            buffer = []
            continue

        if collecting and ln == "next":
            if current_vdom and buffer:
                vdoms[current_vdom] = buffer.copy()
            current_vdom = None
            buffer = []
            continue

        if collecting and ln.startswith("end"):
            break

        if current_vdom:
            buffer.append(ln)

    return vdoms
