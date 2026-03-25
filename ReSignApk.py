import hashlib
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path


def run():
    root = Path(__file__).resolve().parent
    load_env_config(root)
    in_apk = resolve_input_apk(root)
    if not in_apk.exists():
        print(str(in_apk) + " 不存在")
        sys.exit(1)
    print_keystore_info(root)
    before = get_apk_signer_digests(in_apk, root)
    print_digests("签名之前", before)
    out_apk = resign_apk(in_apk, root)
    verify_apk(out_apk, root)
    after = get_apk_signer_digests(out_apk, root)
    print_digests("签名之后", after)


def resolve_input_apk(root: Path) -> Path:
    if len(sys.argv) >= 2 and sys.argv[1].strip():
        p = Path(sys.argv[1].strip())
        if not p.is_absolute():
            p = (root / p).resolve()
        return p
    return root / "res" / "app-release.apk"


def resign_apk(in_apk: Path, root: Path) -> Path:
    apksigner = os.environ.get("APKSIGNER_PATH") or "/Users/huhuijie/Library/Android/sdk/build-tools/34.0.0/apksigner"
    if shutil.which(apksigner) is None and not Path(apksigner).exists():
        print("未找到 apksigner: " + apksigner)
        sys.exit(1)

    keystore, key_alias, store_password, key_password = resolve_keystore_config(root)

    dist_dir = root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    out_apk = dist_dir / (in_apk.stem + "-resigned.apk")

    env = dict(os.environ)
    env["PLATAYA_STORE_PASSWORD"] = store_password
    env["PLATAYA_KEY_PASSWORD"] = key_password
    cmd = [
        apksigner,
        "sign",
        "--ks",
        str(keystore),
        "--ks-key-alias",
        key_alias,
        "--ks-pass",
        "env:PLATAYA_STORE_PASSWORD",
        "--key-pass",
        "env:PLATAYA_KEY_PASSWORD",
        "--out",
        str(out_apk),
        str(in_apk),
    ]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    print(r.stdout)
    if r.returncode != 0:
        print("重签名失败")
        sys.exit(r.returncode)
    print("重签名完成: " + str(out_apk))
    return out_apk


def resolve_keystore_config(root: Path):
    jks_rel = os.environ.get("JKS_PATH")
    if not jks_rel:
        candidate = root / "res" / "plataYA.jks"
        if candidate.exists():
            jks_rel = "plataYA.jks"
        else:
            print("未提供环境变量 JKS_PATH，且默认证书不存在: " + str(candidate))
            sys.exit(1)
    keystore = root / "res" / jks_rel
    if not keystore.exists():
        print("未找到签名证书: " + str(keystore))
        sys.exit(1)

    store_password = os.environ.get("PLATAYA_STORE_PASSWORD")
    key_password = os.environ.get("PLATAYA_KEY_PASSWORD")
    key_alias = os.environ.get("PLATAYA_KEY_ALIAS") or "plataya"
    if not store_password or not key_password:
        print("未提供签名密码（环境变量 PLATAYA_STORE_PASSWORD / PLATAYA_KEY_PASSWORD）")
        sys.exit(1)

    return keystore, key_alias, store_password, key_password


def print_keystore_info(root: Path):
    keystore, key_alias, store_password, _ = resolve_keystore_config(root)
    keytool = shutil.which("keytool")
    print("JKS: " + str(keystore))
    print("JKS_ALIAS: " + str(key_alias))
    if not keytool:
        print("未检测到 keytool，跳过打印证书详情（可安装/配置 JDK 后再试）")
        return

    list_cmd = [
        keytool,
        "-list",
        "-v",
        "-keystore",
        str(keystore),
        "-alias",
        key_alias,
    ]
    r = subprocess.run(
        list_cmd,
        input=store_password + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    list_text = r.stdout or ""

    parsed = {
        "keystore_type": None,
        "owner": None,
        "issuer": None,
        "serial": None,
        "valid": None,
        "sha1": None,
        "md5": None,
    }
    for raw in list_text.splitlines():
        line = raw.strip()
        if line.startswith("Keystore type:"):
            parsed["keystore_type"] = line.split("Keystore type:", 1)[1].strip()
        elif line.startswith("密钥库类型:"):
            parsed["keystore_type"] = line.split("密钥库类型:", 1)[1].strip()
        elif line.startswith("Owner:"):
            parsed["owner"] = line.split("Owner:", 1)[1].strip()
        elif line.startswith("所有者:"):
            parsed["owner"] = line.split("所有者:", 1)[1].strip()
        elif line.startswith("Issuer:"):
            parsed["issuer"] = line.split("Issuer:", 1)[1].strip()
        elif line.startswith("发布者:"):
            parsed["issuer"] = line.split("发布者:", 1)[1].strip()
        elif line.startswith("颁发者:"):
            parsed["issuer"] = line.split("颁发者:", 1)[1].strip()
        elif line.startswith("Serial number:"):
            parsed["serial"] = line.split("Serial number:", 1)[1].strip()
        elif line.startswith("序列号:"):
            parsed["serial"] = line.split("序列号:", 1)[1].strip()
        elif line.startswith("Valid from:"):
            parsed["valid"] = line.split("Valid from:", 1)[1].strip()
        elif line.startswith("有效期为:"):
            parsed["valid"] = line.split("有效期为:", 1)[1].strip()
        elif line.startswith("SHA1:"):
            parsed["sha1"] = line.split("SHA1:", 1)[1].strip().replace(":", "").lower()
        elif line.startswith("MD5:"):
            parsed["md5"] = line.split("MD5:", 1)[1].strip().replace(":", "").lower()

    export_cmd = [
        keytool,
        "-exportcert",
        "-rfc",
        "-keystore",
        str(keystore),
        "-alias",
        key_alias,
    ]
    r2 = subprocess.run(
        export_cmd,
        input=store_password + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    pem = r2.stdout or ""
    try:
        begin = "-----BEGIN CERTIFICATE-----"
        end = "-----END CERTIFICATE-----"
        start = pem.find(begin)
        stop = pem.find(end)
        pem_cert = pem
        if start != -1 and stop != -1:
            pem_cert = pem[start : stop + len(end)]
        der = ssl.PEM_cert_to_DER_cert(pem_cert)
        sha1 = hashlib.sha1(der).hexdigest()
        md5 = hashlib.md5(der).hexdigest()
        parsed["sha1"] = parsed["sha1"] or sha1
        parsed["md5"] = parsed["md5"] or md5
    except Exception:
        pass

    if parsed["keystore_type"]:
        print("JKS_TYPE: " + str(parsed["keystore_type"]))
    if parsed["owner"]:
        print("JKS_OWNER: " + str(parsed["owner"]))
    if parsed["issuer"]:
        print("JKS_ISSUER: " + str(parsed["issuer"]))
    if parsed["serial"]:
        print("JKS_SERIAL: " + str(parsed["serial"]))
    if parsed["valid"]:
        print("JKS_VALID: " + str(parsed["valid"]))
    if parsed["sha1"] or parsed["md5"]:
        print(f"JKS_DIGEST: SHA-1={parsed['sha1'] or '-'}  MD5={parsed['md5'] or '-'}")
    if r.returncode != 0:
        print("keytool -list 执行失败，输出如下：")
        print(list_text)


def get_apk_signer_digests(apk: Path, root: Path) -> dict:
    apksigner = os.environ.get("APKSIGNER_PATH") or "/Users/huhuijie/Library/Android/sdk/build-tools/34.0.0/apksigner"
    if shutil.which(apksigner) is None and not Path(apksigner).exists():
        return {"error": "未找到 apksigner: " + apksigner}

    cmd = [apksigner, "verify", "--verbose", "--print-certs", str(apk)]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    sha1 = None
    md5 = None
    for raw in (r.stdout or "").splitlines():
        line = raw.strip()
        if "certificate SHA-1 digest:" in line:
            sha1 = line.split("certificate SHA-1 digest:", 1)[1].strip()
        elif "certificate MD5 digest:" in line:
            md5 = line.split("certificate MD5 digest:", 1)[1].strip()
    out = {"sha1": sha1, "md5": md5}
    if r.returncode != 0:
        out["error"] = "apksigner verify 失败"
        out["verify_output"] = r.stdout
    return out


def print_digests(label: str, digests: dict):
    sha1 = digests.get("sha1")
    md5 = digests.get("md5")
    err = digests.get("error")
    if err:
        print(f"{label}：获取签名摘要失败（{err}）")
        if digests.get("verify_output"):
            print(digests["verify_output"])
        return
    if not sha1 and not md5:
        print(f"{label}：未解析到证书摘要（可能 APK 未签名或输出格式变化）")
        return
    print(f"{label}：SHA-1={sha1 or '-'}  MD5={md5 or '-'}")


def verify_apk(apk: Path, root: Path):
    apksigner = os.environ.get("APKSIGNER_PATH") or "/Users/huhuijie/Library/Android/sdk/build-tools/34.0.0/apksigner"
    if shutil.which(apksigner) is None and not Path(apksigner).exists():
        print("未找到 apksigner: " + apksigner)
        return
    cmd = [apksigner, "verify", "--verbose", "--print-certs", str(apk)]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print("签名校验失败: " + str(apk))
        sys.exit(r.returncode)
    print("签名校验通过: " + str(apk))


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
