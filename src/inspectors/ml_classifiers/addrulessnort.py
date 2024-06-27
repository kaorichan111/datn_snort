import subprocess
import os
import numpy as np
def kill_snort():
    # Define the command as a string
    command = "ps aux | grep snort | grep Sl+ | awk '{print $2}' | xargs kill -1"

    # Use subprocess to execute the command
    try:
        # Run the command
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Print the output and error (if any)
        print("Output:\n", result.stdout)
        print("Error:\n", result.stderr)
    except subprocess.CalledProcessError as e:
        # Handle any errors that occurred during the execution
        print(f"An error occurred: {e}")
        print(f"Return code: {e.returncode}")
        print(f"Output: {e.output}")
        print(f"Stderr: {e.stderr}")

def add_rules():
    # Get the current working directory

    current_directory = os.getcwd()



    # Print the current working directory

    print("Current working directory:", current_directory)
    # Đọc nội dung của timeouted_connections_id.txt và timeouted_connections_results.txt
    with open('tmp/timeouted_connections_id.txt', 'r') as file1, open('tmp/timeouted_connections_results.txt', 'r') as file2, open('tmp/timeouted_connections.txt') as file4:
        file1_lines = file1.readlines()
        file2_lines = file2.readlines()
        file4_lines = file4.readlines()

    # Lọc các dòng từ tmp/timeouted_connections_id.txt mà ứng với các dòng trong tmp/timeouted_connections_results.txt có giá trị là 1.0
    filtered_lines_file1 = [line.strip() for line, value in zip(file1_lines, file2_lines) if value.strip() == '1.0']
    filtered_lines_file4 = [line.strip() for line, value in zip(file4_lines, file2_lines) if value.strip() == '1.0']

    # Chuyển đổi các dòng đã lọc thành các mảng con và gộp vào một mảng lớn
    result = []
    for idx,line in enumerate(filtered_lines_file1):
        protocol, src_dst = line.split('-', 1)
        src, dst = src_dst.split('-')
        src_ip, src_port = src.rsplit(':', 1)
        dst_ip, dst_port = dst.rsplit(':', 1)
        attribute_12 = float(filtered_lines_file4[idx].split()[11])
        result.append([protocol, src_ip, src_port, dst_ip, dst_port, attribute_12])

    # Thống kê số lượng các dst_port
    dst_port_count = {}
    for rule in result:
        dst_port = rule[4]
        attribute_12 = rule[5]
        if dst_port in dst_port_count:
            dst_port_count[dst_port][0] += 1
            dst_port_count[dst_port][1].append(attribute_12)
        else:
            dst_port_count[dst_port] = [1, [attribute_12]]
    print(dst_port_count)
    #Lọc các dst_port có số lượng lớn hơn 20
    #high_count_ports = {port: count for port, count in dst_port_count.items() if count > 20}
    filtered_ports = {port: np.mean(data[1]) for port, data in dst_port_count.items() if data[0] > 20}
    print(filtered_ports)
    #Đọc nội dung của /usr/local/etc/rules/local.rules và tìm sid lớn nhất
    if bool(filtered_ports):
        try:
            with open('/usr/local/etc/rules/local.rules', 'r') as file3:
                existing_rules = file3.readlines()
                # Tìm sid lớn nhất và lưu các luật không bao gồm sid
                max_sid = 0
                existing_rules_without_sid = []
                for line in existing_rules:
                    if "sid:" in line:
                        sid_start = line.index("sid:") + 4
                        sid_end = line.index(";", sid_start)
                        sid = int(line[sid_start:sid_end].strip())
                        if sid > max_sid:
                            max_sid = sid
                        # Bỏ phần sid để so sánh
                        rule_without_sid = line[:sid_start].strip()
                        existing_rules_without_sid.append(rule_without_sid)
        except FileNotFoundError:
            existing_rules = []
            existing_rules_without_sid = []
            max_sid = 1000001  # Bắt đầu từ sid 1000003 nếu file không tồn tại

        # Tạo ra các chuỗi luật Snort với sid mới
        snort_rules = []
        current_sid = max_sid + 1
        print(current_sid)
        for dst_port, avcount in filtered_ports.items():
            rule = f'alert tcp any any -> any {dst_port} (msg:"TCP SYN Flood detected"; detection_filter:track by_dst, count {round(avcount)}, seconds 1; sid:{current_sid}; )'
            rule_without_sid = rule[:rule.index("sid:") + 4].strip()  # Bỏ phần sid để so sánh
            if rule_without_sid not in existing_rules_without_sid:
                snort_rules.append(rule)
                current_sid += 1
        print(snort_rules)
        existing_dst_ports = {}
        print(existing_rules)
        if existing_rules:
            existing_dst_ports = {rule.split('-> any ')[1].split(' ')[0] for rule in existing_rules}
            print(existing_dst_ports)
        # Kiểm tra và ghi thêm các luật chưa tồn tại vào /usr/local/etc/rules/local.rules
        a = False
        with open('/usr/local/etc/rules/local.rules', 'a') as f3:
            for rule in snort_rules:
                # Kiểm tra xem luật có tồn tại không (chỉ xét dst_port)
                dst_port = rule.split('-> any ')[1].split(' ')[0]
                if dst_port not in existing_dst_ports:
                    f3.write(rule + '\n')
                    a = True
        if a:
            kill_snort()
        print("Các luật Snort đã được kiểm tra và ghi thêm vào /usr/local/etc/rules/local.rules nếu chưa tồn tại.")
