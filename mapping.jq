split("\n")|map(split(","))|
   map({"pod_id": 0,
        "pod_name":.[0],
        "is_internet_connected":.[1],
        "is_root":.[2],
        "is_privileged":.[3],
        "is_port_opened":.[4],
        "confidentiality_level":.[5],
        "availability_level":.[6],
        "integrity_level":.[7],
        "scanner": -SCANNER-,
        "scan_result_id":.[8],
})
