import os
import re
import json
import time
import datetime as dt
from functools import wraps     # 데코레이터로 감싸면 wrapper 함수가 원본을 덮어쓰면서 __doc__도 Noneㅇ로 사


# 함수 실행 시간 측정 (데코레이터 사용)
def log_execution_time(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"[{func.__name__}] 실행시간: {elapsed:.4f}초")
        return result
    return wrapper



# 로그 한 줄이 성공적으로 파싱될 때마다 호출 (총 처리한 로그 줄의 개수 집계)
total_processed = 0

def increment_counter(n=1):
    global total_processed
    total_processed += n
    

# 호출될 때마다 1씩 증가하는 독립적인 카운터 함수(increment)를 만들어 반환하는 클로저 생성
def make_alert_counter():
    count = 0
    def increment():
        nonlocal count
        count += 1
        return count
    return increment


# 로그 형식이 잘못됐을 때 구분해서 처리하기 위한 커스텀 예외 클래스
class InvalidLogFromatError(Exception):
    pass


# 로그 파일을 읽고 의심스러운 이벤트를 탐지하는 클래스
class SecurityLogAnalyzer:
    SUSPICIOUS_KEYWORDS = ["failed login", "unauthorized", "sql injection", "port scan"]

    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.records = []               # 빈 리스트 생성

    def load_files(self):
        assert os.path.isdir(self.log_dir), f"디렉토리가 존재하지 않습니다: {self.log_dir}"

        for filename in os.listdir(self.log_dir):
            if not filename.endswith(".log"):
                continue                                                    #현재의 반복을 즉시 중단하고, 다음 파일로 넘어
            filepath = os.path.join(self.log_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except (IOError, UnicodeDecodeError) as e:
                print(f"파일 읽기 실패: {filename} ({e})")
                continue

            self.records.extend(self._parse_lines(lines, filename))

    # 파일의 각 줄을 순회하며 _split_log_line()으로 파싱, 성공한 줄만 딕셔너리로 만들어 리스트로 변환
    def _parse_lines(self, lines, source):
        parsed = []
        for idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                timestamp, level, message = self._split_log_line(line)
            except InvalidLogFormatError:
                continue
            parsed.append({
                "source": source,
                "line_no": idx,
                "timestamp": timestamp,
                "level": level,
                "message": message,
                })
            increment_counter()
        return parsed

    # 정규식으로 로그 한 줄을 (타임스탬프, 레벨, 메시지)로 분해
    def _split_log_line(self, line):
        # 예: "2026-09-04 10:00:01 [ERROR] failed login attempt from 1.2.3.4"
        match = re.match(r"^(\S+ \S+) \[(\w+)] (.+)$", line)
        if not match:
            raise InvalidLogFromatError(f"형식 오류: {line}")
        return match.groups()


    # self.records 중 의심 키워드(SUSPICIOUS_KEYWORDS)가 포함된 메시지만 필터링해서 반환
    def get_suspicious_records(self):
        return [
            r for r in self.records
            if any(kw in r["message"].lower() for kw in self.SUSPICIOUS_KEYWORDS)
            ]

    def count_by_level(self):
        levels = {r["level"] for r in self.records}
        return {level: len([r for r in self.records if r["level"] == level]) for level in levels}


    # self.records 중 레벨이 ERROR인 것만 하나씩 yield하는 제네레이터
    def iter_errors(self):
        for r in self.records:
            if r["level"] == "ERROR":
                yield r

    # 각 레코드 메시지에서 정규식으로 IP 주소를 찾아 리스트로 반환
    def get_source_ip_summary(self):
        ip_pattern = re.compile(r"\d{1, 3}(?:\.\d{1, 3}){3}")
        messages_with_ip = filter(lambda r: ip_pattern.search(r["message"]), self.records)
        ips = list(map(lambda r: ip_pattern.search(r["message"]).group(), messages_with_ip))
        return ips


# 두 리스트를 짝지어 {소스: 개수} 형태의 딕셔너리로 병합 (소스별 리포트 병합)
def merge_reports(sources, counts):
    return dict(zip(sources, counts))

# records를 JSON 파일로 저장. @log_execution_time이 붙어있어 저장 소요 시간도 출력됨
@log_execution_time
def save_report(records, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"리포트 저장 완료: {output_path} (총 {len(records)}건)")


# ip, reason 키워드 인자를 받아 알림 문자열 생성. 필수 키 없으면 ValueError 발생
def build_alert(**kwargs):
    required = {"ip", "reason"}
    if not required.issubset(kwargs.keys()):
        raise ValueError("필수 필드 누락")
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{now}] ALERT IP={kwargs['ip']} 사유={kwargs['reason']}"


def main():
    analyzer = SecurityLogAnalyzer("./sample_logs")

    # 데모용 샘플 로그 디렉토리 생성
    if not os.path.isdir("./sample_logs"):
        os.makedirs("./sample_logs")
        with open("./sample_logs/auth.log", "w", encoding="utf-8") as f:
            f.write(
                "2026-09-04 10:00:01 [ERROR] failed login attempt from 1.2.3.4\n"
                "2026-09-04 10:00:05 [INFO] normal login from 10.0.0.5\n"
                "2026-09-04 10:00:09 [WARNING] port scan detected from 5.6.7.8\n"
            )

    analyzer.load_files()

    suspicious = analyzer.get_suspicious_records()
    level_counts = analyzer.count_by_level()
    alert_counter = make_alert_counter()

    print(f"총 처리 라인 수: {total_processed}")
    print(f"레벨별 집계: {level_counts}")
    print(f"의심 이벤트 수: {len(suspicious)}")

    for err in analyzer.iter_errors():
        print(f"[ERROR] {err['source']}:{err['line_no']} - {err['message']}")

    for ip in analyzer.get_source_ip_summary():
        n = alert_counter()
        print(f"({n}) 탐지된 IP: {ip}")

    alert_info = {"ip": "1.2.3.4", "reason": "다중 로그인 실패"}
    print(build_alert(**alert_info))

    save_report(suspicious, "suspicious_report.json")


if __name__ == "__main__":
    main()
    
