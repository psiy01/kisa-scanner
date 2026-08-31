#!/bin/bash
# 랩 환경 취약점 조치 스크립트
# ⚠️ 진단 대상 컨테이너 내부에서만 실행할 것

set -u
echo "[*] 조치 시작"

# ── 계정 관리 ────────────────────────────
# U-01: root 원격 접속 차단
sed -i 's/^\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo "  [+] U-01 PermitRootLogin no"

# U-02, U-03, U-08: 패스워드 정책 (주석 처리된 경우 포함)
sed -i 's/^#*\s*PASS_MIN_LEN.*/PASS_MIN_LEN 8/'   /etc/login.defs
sed -i 's/^#*\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^#*\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/'  /etc/login.defs
echo "  [+] U-02,03,08 패스워드 정책"

# U-06: 계정 잠금 임계값
if ! grep -q 'pam_faillock' /etc/pam.d/common-auth 2>/dev/null; then
  echo 'auth required pam_faillock.so deny=5 unlock_time=120' \
    >> /etc/pam.d/common-auth
fi
echo "  [+] U-06 계정 잠금"

# U-07: su 제한
if ! grep -q '^auth.*pam_wheel' /etc/pam.d/su 2>/dev/null; then
  echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su
fi
echo "  [+] U-07 su 제한"

# U-12: 세션 타임아웃
if ! grep -q 'TMOUT' /etc/profile; then
  printf '\nTMOUT=600\nexport TMOUT\n' >> /etc/profile
fi
echo "  [+] U-12 세션 타임아웃"

# ── 파일 권한 ────────────────────────────
# U-14: shadow 권한
chmod 400 /etc/shadow
echo "  [+] U-14 /etc/shadow 400"

# U-18: 불필요한 SUID 제거
chmod -s /usr/local/bin/find-suid 2>/dev/null
echo "  [+] U-18 SUID 제거"

# U-19: world writable 제거
chmod o-w /opt/app/config.ini 2>/dev/null
echo "  [+] U-19 world writable 제거"

# U-20: 소유자 없는 파일 정리
chown root:root /opt/orphan.txt 2>/dev/null
echo "  [+] U-20 소유자 지정"

# ── 서비스 ──────────────────────────────
# U-29: crontab 권한
chmod 640 /etc/crontab
echo "  [+] U-29 /etc/crontab 640"

# U-32: cron 접근 통제
echo 'root' > /etc/cron.allow
chmod 640 /etc/cron.allow
echo "  [+] U-32 cron.allow 생성"

# ── 로그 ────────────────────────────────
# U-34: 원격 로그 전송
if ! grep -q '^\*\.\* *@@' /etc/rsyslog.conf 2>/dev/null; then
  echo '*.* @@192.168.100.10:514' >> /etc/rsyslog.conf
fi
echo "  [+] U-34 원격 로그 설정"

# U-42: 로그 보관 기간
sed -i 's/^\s*rotate .*/rotate 24/' /etc/logrotate.conf
echo "  [+] U-42 로그 보관 24주"

echo "[*] 조치 완료. SSH 재시작 필요 시 수동 수행"