import subprocess
import sys
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
import os


def run():
    root = Path(__file__).resolve().parent
    load_env_config(root)
    apk = root / "res" / os.environ.get("APK_PATH")
    if not apk.exists():
        print(str(apk) + " 不存在")
        sys.exit(1)
    if shutil.which("apktool") is None:
        print("未检测到 apktool，可在系统安装后重试")
        sys.exit(1)
    out_dir = root / "out" / "app-release"
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["apktool", "d", str(apk), "-o", str(out_dir), "-f"]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(r.stdout)
    if r.returncode != 0:
        sys.exit(r.returncode)
    print("解析完成，输出目录: " + str(out_dir))
    update_network_security_config(out_dir)
    update_manifest_extract_native_libs(out_dir)
    out_apk = build_apk(out_dir, root)
    sign_apk(out_apk, root)


def update_network_security_config(out_dir: Path):
    manifest = out_dir / "AndroidManifest.xml"
    if not manifest.exists():
        print("未找到 AndroidManifest.xml")
        sys.exit(1)
    tree = ET.parse(manifest)
    root_el = tree.getroot()
    app = root_el.find("application")
    if app is None:
        print("Manifest 中未找到 application 节点")
        sys.exit(1)
    ns = "{http://schemas.android.com/apk/res/android}"
    modified = False
    clear_key = ns + "usesCleartextTraffic"
    if app.attrib.get(clear_key) == "true":
        del app.attrib[clear_key]
        modified = True
        print("已删除 application 中 android:usesCleartextTraffic=true")
    nsc_key = ns + "networkSecurityConfig"
    ref = app.attrib.get(nsc_key)
    if not ref or not ref.startswith("@xml/"):
        name = "network_security_config"
        app.set(nsc_key, "@xml/" + name)
        modified = True
        print("已添加 application 中 android:networkSecurityConfig=@xml/" + name)
    else:
        name = ref.split("/", 1)[1]
    target = out_dir / "res" / "xml" / (name + ".xml")
    target.parent.mkdir(parents=True, exist_ok=True)
    content = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>
"""
    target.write_text(content, encoding="utf-8")
    print("已更新网络安全配置: " + str(target))
    if modified:
        tree.write(manifest, encoding="utf-8", xml_declaration=True)


def update_manifest_extract_native_libs(out_dir: Path):
    manifest = out_dir / "AndroidManifest.xml"
    if not manifest.exists():
        print("未找到 AndroidManifest.xml")
        sys.exit(1)
    tree = ET.parse(manifest)
    root = tree.getroot()
    app = root.find("application")
    if app is None:
        print("Manifest 中未找到 application 节点")
        sys.exit(1)
    ns = "{http://schemas.android.com/apk/res/android}"
    key = ns + "extractNativeLibs"
    if key in app.attrib:
        app.set(key, "true")
        tree.write(manifest, encoding="utf-8", xml_declaration=True)
        print("已设置 application 中 android:extractNativeLibs=true")
    else:
        print("application 未配置 android:extractNativeLibs，保持不变")


def build_apk(out_dir: Path, root: Path):
    dist_dir = root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    out_apk = dist_dir / "app-release-rebuilt.apk"
    cmd = ["apktool", "b", str(out_dir), "-o", str(out_apk), "-f"]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(r.stdout)
    if r.returncode != 0:
        sys.exit(r.returncode)
    if out_apk.exists():
        print("编译完成: " + str(out_apk))
    else:
        print("编译完成，但未找到输出文件，请检查日志")
    return out_apk


def sign_apk(out_apk: Path, root: Path):
    apksigner = os.environ.get("APKSIGNER_PATH") or "/Users/huhuijie/Library/Android/sdk/build-tools/34.0.0/apksigner"
    if shutil.which(apksigner) is None and not Path(apksigner).exists():
        print("未找到 apksigner: " + apksigner)
        return
    keystore = root / "res" / os.environ.get("JKS_PATH")
    if not keystore.exists():
        print("未找到签名证书: " + str(keystore))
        return
    store_password = os.environ.get("PLATAYA_STORE_PASSWORD")
    key_password = os.environ.get("PLATAYA_KEY_PASSWORD")
    key_alias = os.environ.get("PLATAYA_KEY_ALIAS") or "plataya"
    if not store_password or not key_password:
        print("未提供签名密码（环境变量 PLATAYA_STORE_PASSWORD / PLATAYA_KEY_PASSWORD），跳过签名")
        return
    signed_apk = out_apk.with_name(out_apk.stem + "-signed.apk")
    env = dict(os.environ)
    env["PLATAYA_STORE_PASSWORD"] = store_password
    env["PLATAYA_KEY_PASSWORD"] = key_password
    cmd = [
        apksigner,
        "sign",
        "--ks", str(keystore),
        "--ks-key-alias", key_alias,
        "--ks-pass", "env:PLATAYA_STORE_PASSWORD",
        "--key-pass", "env:PLATAYA_KEY_PASSWORD",
        "--out", str(signed_apk),
        str(out_apk),
    ]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    print(r.stdout)
    if r.returncode != 0:
        print("签名失败")
        sys.exit(r.returncode)
    print("签名完成: " + str(signed_apk))


def load_env_config(root: Path):
    cfg = root / ".okapk.env"
    if not cfg.exists():
        return
    for line in cfg.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k and v and k not in os.environ:
            os.environ[k] = v


if __name__ == "__main__":
    run()
