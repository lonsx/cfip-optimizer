#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用 NAS 上的官方 fnpack 工具构建全平台（x86_64 + aarch64）规范的 FPK 包。"""
import os, sys, time, paramiko, json

PW = "a12213443"
NAS = "192.168.1.12"
APP = "cfip-opt"
LOCAL = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = "/vol4/@appdata/cfip-opt/build"

def log(*a): print(*a, flush=True)

def main():
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(NAS, 22, "wb", PW, timeout=20, banner_timeout=40)

    def sudo(cmd, t=180):
        q = "'" + cmd.replace("'", "'\\''") + "'"
        si, so, se = cli.exec_command("echo %s | sudo -S -p '' bash -c %s" % (PW, q), timeout=t)
        return so.channel.recv_exit_status(), so.read().decode("utf-8", "replace"), se.read().decode("utf-8", "replace")

    def upload_tree(local_dir, remote_dir):
        sftp = cli.open_sftp()
        sudo("mkdir -p " + remote_dir)
        sudo("chmod 777 " + remote_dir)
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir)
            target = remote_dir if rel == "." else remote_dir + "/" + rel.replace(os.sep, "/")
            sudo("mkdir -p " + target)
            sudo("chmod 777 " + target)
            for f in files:
                lp = os.path.join(root, f)
                sftp.put(lp, target + "/" + f)
        sftp.close()

    log("== 1. 上传最新 go-web 源码并双架构编译（x86_64 + aarch64）==")
    upload_tree(os.path.join(LOCAL, "go-web"), BUILD + "/go-web")

    rc, out, err = sudo(
        "docker run --rm "
        "-v %s:/src -w /src/go-web "
        "-e CGO_ENABLED=0 "
        "-e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath "
        "golang:1.22-alpine "
        "sh -c '"
        "GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=\"-s -w\" -o /src/cfip-opt-x86_64 ./cmd/cfip-opt && "
        "GOOS=linux GOARCH=arm64 go build -trimpath -ldflags=\"-s -w\" -o /src/cfip-opt-aarch64 ./cmd/cfip-opt && "
        "echo BUILD_OK && ls -lh /src/cfip-opt-*' "
        "2>&1" % BUILD
    )
    log("编译输出:\n", out.strip())
    if rc != 0:
        cli.close()
        sys.exit(f"双架构编译失败 rc={rc}")

    # 取回两个二进制到本地 dist/
    os.makedirs(os.path.join(LOCAL, "dist"), exist_ok=True)
    sftp = cli.open_sftp()
    sftp.get(BUILD + "/cfip-opt-x86_64", os.path.join(LOCAL, "dist", "cfip-opt-x86_64"))
    sftp.get(BUILD + "/cfip-opt-aarch64", os.path.join(LOCAL, "dist", "cfip-opt-aarch64"))
    sftp.get(BUILD + "/cfip-opt-aarch64", os.path.join(LOCAL, "dist", "cfip-opt"))
    sftp.close()
    log("本地已同步双架构二进制: dist/cfip-opt-x86_64, dist/cfip-opt-aarch64")

    log("\n== 2. 上传 pkg 目录结构到 /tmp/cfip-opt-fnpack ==")
    sudo("rm -rf /tmp/cfip-opt-fnpack")
    upload_tree(os.path.join(LOCAL, "pkg"), "/tmp/cfip-opt-fnpack")

    # 上传编译出的双架构二进制
    sudo("mkdir -p /tmp/cfip-opt-fnpack/app/bin")
    sftp = cli.open_sftp()
    sftp.put(os.path.join(LOCAL, "dist", "cfip-opt-x86_64"), "/tmp/cfip-opt-fnpack/app/bin/cfip-opt-x86_64")
    sftp.put(os.path.join(LOCAL, "dist", "cfip-opt-aarch64"), "/tmp/cfip-opt-fnpack/app/bin/cfip-opt-aarch64")
    sftp.close()

    # 默认建立相对软链 cfip-opt -> cfip-opt-aarch64
    sudo("cd /tmp/cfip-opt-fnpack/app/bin && ln -sf cfip-opt-aarch64 cfip-opt")
    sudo("chmod 755 /tmp/cfip-opt-fnpack/app/bin/* /tmp/cfip-opt-fnpack/cmd/*")

    log("\n== 3. 检查构建目录中的 manifest 与 wizard ==")
    rc, out, _ = sudo("grep -E 'appname|version|platform|desktop_applaunchname' /tmp/cfip-opt-fnpack/manifest; echo '---'; cat /tmp/cfip-opt-fnpack/wizard/uninstall")
    log(out.strip())

    log("\n== 4. 执行 fnpack build 构建全平台 FPK ==")
    rc, out, err = sudo("cd /tmp/cfip-opt-fnpack && fnpack build")
    log(out.strip())
    if rc != 0:
        log("fnpack build 失败:\n", err)
        cli.close()
        sys.exit(1)

    log("\n== 5. 产物校验与拉回 ==")
    rc, out, err = sudo("ls -la /tmp/cfip-opt-fnpack/*.fpk")
    log(out.strip())

    # 取回本地 dist/cfip-opt_1.1.2_all.fpk
    all_fpk = os.path.join(LOCAL, "dist", "cfip-opt_1.1.2_all.fpk")
    sftp = cli.open_sftp()
    sftp.get("/tmp/cfip-opt-fnpack/cfip-opt.fpk", all_fpk)
    sftp.close()
    log("已生成并拉回全平台安装包: dist/cfip-opt_1.1.2_all.fpk, 大小: %.2f MB" % (os.path.getsize(all_fpk) / 1048576.0))

    # 清理旧包
    for old in ("cfip-opt_1.1.0_all.fpk", "cfip-opt_1.1.0_arm.fpk", "cfip-opt_1.1.1_all.fpk"):
        old_p = os.path.join(LOCAL, "dist", old)
        if os.path.exists(old_p):
            os.remove(old_p)
            log("已清理旧包:", old)

    # 清理 NAS 上的临时构建目录
    sudo("rm -rf /tmp/cfip-opt-fnpack " + BUILD)
    log("已清理 NAS /tmp 临时构建目录与构建缓存")

    cli.close()
    log("\n== 全平台构建与打包完成！==")

if __name__ == "__main__":
    main()
