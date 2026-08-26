"""명령 실행 추상화. 로컬/SSH를 같은 인터페이스로 다룬다."""
import subprocess
from abc import ABC, abstractmethod

import paramiko


class Executor(ABC):
    @abstractmethod
    def run(self, command: str) -> tuple[str, int]:
        """명령을 실행하고 (출력, 종료코드)를 반환."""
        ...


class LocalExecutor(Executor):
    def run(self, command: str) -> tuple[str, int]:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True
        )
        return (proc.stdout + proc.stderr).strip(), proc.returncode


class SSHExecutor(Executor):
    def __init__(self, host: str, port: int, username: str, password: str):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=host, port=port,
            username=username, password=password,
            timeout=10,
        )

    def run(self, command: str) -> tuple[str, int]:
        _, stdout, stderr = self.client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode() + stderr.read().decode()
        return output.strip(), exit_code

    def close(self) -> None:
        self.client.close()