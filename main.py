import tkinter as tk
from tkinter import filedialog
import csv
import datetime

from config_loader import load_config_file
from parser_address import parse_addresses
from parser_service import parse_services
from policy_checker import parse_policies, check_policy_overlap


# ============================================================
# GUI: ファイル選択 (.conf / .log / .txt 対応)
# ============================================================

def select_file():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="FortiGate コンフィグファイルを選択",
        filetypes=[
            ("FortiGate Config", "*.conf"),
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ]
    )
    return file_path


# ============================================================
# VDOMモード判定
# ============================================================

def detect_vdom_mode(lines):
    for ln in lines:
        s = ln.strip()
        if "set vdom-mode" in s:
            return s.split("set vdom-mode")[1].strip()
    return "no-vdom"


# ============================================================
# #global_vdom=0:vd_name=XXX/XXX から VDOM名を取得
# ============================================================

def detect_vdom_name_from_global(lines):
    for ln in lines:
        s = ln.strip()
        if s.startswith("#global_vdom=") and "vd_name=" in s:
            try:
                part = s.split("vd_name=")[1]
                name = part.split("/")[0]
                return name.strip()
            except:
                pass
    return None


# ============================================================
# config vdom の edit <VDOM名> から取得（通常バックアップ用）
# ============================================================

def detect_single_vdom_name(lines):
    inside_vdom_block = False

    for ln in lines:
        s = ln.strip()

        if s == "config vdom":
            inside_vdom_block = True
            continue

        if inside_vdom_block:
            if s.startswith("edit "):
                return s.split("edit")[1].strip().replace('"', "")
            if s == "end":
                break

    return None


# ============================================================
# FortiOS 7.6 の VDOM一体型構造に対応した split_vdoms
# ============================================================

def split_vdoms(lines):
    vdoms = {}
    current_vdom = None
    inside_vdom_block = False

    for ln in lines:
        s = ln.strip()

        if s == "config vdom":
            inside_vdom_block = True
            continue

        if inside_vdom_block:

            if s.startswith("edit "):
                current_vdom = s.split("edit")[1].strip().replace('"', "")
                vdoms[current_vdom] = []
                continue

            if s == "next":
                current_vdom = None
                continue

            if s == "end":
                inside_vdom_block = False
                current_vdom = None
                continue

            if current_vdom:
                vdoms[current_vdom].append(ln)

    return vdoms


# ============================================================
# CSV 出力（A〜D列対応）
# ============================================================

def export_csv(result_dict, vdom_name):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"policy_overlap_result_{vdom_name}_{timestamp}.csv"

    with open(output_path, "w", newline="", encoding="cp932") as f:
        writer = csv.writer(f)
        writer.writerow([
            "edit番号",
            "重複しているポリシー番号一覧",
            "最上位の重複ポリシー",
            "重複数"
        ])

        for edit_id, overlaps in result_dict.items():
            top = overlaps[0] if overlaps else ""
            count = len(overlaps)
            writer.writerow([edit_id, ", ".join(overlaps), top, count])

    print(f"[{vdom_name}] CSV 出力完了: {output_path}")


# ============================================================
# メイン処理
# ============================================================

def main():
    print("FortiGate multi-VDOM 重複ポリシー解析ツール")
    print("コンフィグファイルを選択してください...")

    path = select_file()
    if not path:
        print("ファイルが選択されませんでした。終了します。")
        return

    print(f"読み込み中: {path}")
    lines = load_config_file(path)

    vdom_mode = detect_vdom_mode(lines)

    # ============================================================
    # 🔥 単一VDOMの VDOM 名取得ロジック（vd_name対応）
    # ============================================================

    if vdom_mode == "no-vdom":
        print("VDOM無効化を検出しました。単一VDOMとして解析します。")

        vdom_name = detect_vdom_name_from_global(lines)
        if not vdom_name:
            vdom_name = detect_single_vdom_name(lines)
        if not vdom_name:
            vdom_name = "root"

        vdoms = {vdom_name: lines}

    else:
        print("VDOM有効化を検出しました。VDOMを分割します。")
        vdoms = split_vdoms(lines)

        if len(vdoms) == 0:
            print("VDOMブロックが見つかりません。単一VDOMとして解析します。")

            vdom_name = detect_vdom_name_from_global(lines)
            if not vdom_name:
                vdom_name = detect_single_vdom_name(lines)
            if not vdom_name:
                vdom_name = "root"

            vdoms = {vdom_name: lines}

    print(f"VDOM数: {len(vdoms)}")

    # ============================================================
    # VDOMごとに解析
    # ============================================================

    for vdom_name, vdom_lines in vdoms.items():
        print(f"\n===== VDOM: {vdom_name} =====")

        print("address / addrgrp を解析中...")
        address_objects, address_groups = parse_addresses(vdom_lines)

        print("service / service group を解析中...")
        service_objects, service_groups = parse_services(vdom_lines)

        print("policy を解析中...")
        policies = parse_policies(vdom_lines)

        print(f"検出されたポリシー数: {len(policies)}")

        print("重複判定を実行中...")
        result = check_policy_overlap(
            policies,
            address_objects,
            address_groups,
            service_objects,
            service_groups
        )

        print("CSV 出力中...")
        export_csv(result, vdom_name)

    print("\nすべてのVDOMの解析が完了しました。")


if __name__ == "__main__":
    main()
