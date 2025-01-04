#!/usr/bin/env python3

# author: tcneko <tcneko@outlook.com>
# start from: 2023.03
# last test environment: ubuntu 24.04
# description:


# import
import aiohttp
import asyncio
import ipaddress
import json
import numpy
import math
import random
import re
import time
import typer

from typing import List


# function
async def fping(prefix: str):
    ip_network = ipaddress.ip_network(prefix)
    address_count = ip_network.num_addresses
    network_address = str(ip_network.network_address)
    broadcast_address = str(ip_network.broadcast_address)
    fping = await asyncio.create_subprocess_exec(
        "fping",
        "-sq",
        "-c5",
        "-t1000",
        "-g",
        network_address,
        broadcast_address,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    fping_stderr = (await fping.communicate())[1]
    fping_out_list = fping_stderr.decode("utf-8").split("\n")
    fping_out_ip_list = fping_out_list[0:address_count]
    fping_out_summary_list = fping_out_list[address_count:-1]
    alive_addr_list = []
    dead_addr_list = []
    for line in fping_out_ip_list:
        re_out = re.search(r"min/avg/max", line)
        if re_out:
            alive_addr_list.append(line.split(" ")[0])
        else:
            dead_addr_list.append(line.split(" ")[0])
    alive_addr_set = set(alive_addr_list)
    dead_addr_set = set(dead_addr_list)
    alive_count, dead_count, unknown_count = map(
        lambda x: int(x.strip().split(" ")[0]), fping_out_summary_list[-14:-11]
    )
    min_rrt, avg_rrt, max_rrt = map(
        lambda x: float(x.strip().split(" ")[0]), fping_out_summary_list[-5:-2]
    )
    json_msg = {
        "prefix": prefix,
        "alive_addr_count": alive_count,
        "dead_addr_count": dead_count,
        "min_rrt": min_rrt,
        "avg_rrt": avg_rrt,
        "max_rrt": max_rrt,
        "alive_addr_set": alive_addr_set,
        "dead_addr_set": dead_addr_set,
    }
    return json_msg


async def mtr(address: str):
    mtr = await asyncio.create_subprocess_exec(
        "mtr",
        "-njz",
        address,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    mtr_stdout = (await mtr.communicate())[0]
    mtr_out = json.loads(mtr_stdout.decode("utf-8"))
    raw_as_path = list(map(lambda x: x["ASN"], mtr_out["report"]["hubs"]))
    as_path = []
    for raw_asn in raw_as_path:
        try:
            asn = int(raw_asn[2:])
            if (not as_path) or (as_path[-1] != asn):
                as_path.append(asn)
        except:
            continue
    last_hop_avg_rrt = 0
    raw_avg_rrt_list = list(map(lambda x: x["Avg"], mtr_out["report"]["hubs"]))
    for raw_avg_rrt in reversed(raw_avg_rrt_list):
        if raw_avg_rrt != 0:
            last_hop_avg_rrt = raw_avg_rrt
            break
    json_msg = {
        "address": address,
        "as_path": as_path,
        "last_hop_avg_rrt": last_hop_avg_rrt,
    }
    return json_msg


async def scan_prefix(prefix: str, random_seed: int):
    fping_out = await fping(prefix)
    if fping_out["alive_addr_count"] > 0:
        random.seed(random_seed)
        address_list = random.sample(list(fping_out["alive_addr_set"]), 1)
        mtr_out = await mtr(address_list[0])
    else:
        mtr_out = {"address": "", "as_path": [], "last_hop_avg_rrt": 0}
    json_msg = {**fping_out, **mtr_out}
    return json_msg


async def scan_prefix_list(prefix_list: list, max_parallel: int, random_seed: int):
    semaphore = asyncio.Semaphore(max_parallel)

    async def sem_task(task):
        async with semaphore:
            return await task

    aio_task_list = []
    for prefix in prefix_list:
        aio_task_list.append(sem_task(scan_prefix(prefix, random_seed)))
    try:
        analysis_out_list = await asyncio.gather(*aio_task_list, return_exceptions=True)
    except Exception as e:
        print(e)
        json_msg = {"status": "fail", "message": "Analysis task fail"}
        typer.echo(json.dumps(json_msg))
        raise typer.Exit(code=1)
    return analysis_out_list


async def get_announced_prefix(asn: int):
    announced_prefix_list = []
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"
            + str(asn)
        ) as response:
            api_out = await response.json()
    for prefix_data in api_out["data"]["prefixes"]:
        announced_prefix_list.append(prefix_data["prefix"])
    return announced_prefix_list


def reduce_prefix_list(prefix_list: list, ipv4_prefix_len: int):
    reduced_prefix_list = []
    for prefix in prefix_list:
        network = ipaddress.ip_network(prefix)
        if network.version == 4:
            if network.prefixlen < ipv4_prefix_len:
                subnet_list = network.subnets(new_prefix=ipv4_prefix_len)
                for subnet in subnet_list:
                    reduced_prefix_list.append(str(subnet))
            else:
                reduced_prefix_list.append(str(network))
    return reduced_prefix_list


async def get_as_name(asn):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://stat.ripe.net/data/whois/data.json?resource=AS" + str(asn)
            ) as response:
                api_out = await response.json()
        if len(api_out["data"]["authorities"]) > 0:
            flat_record_list = [
                item for sublist in api_out["data"]["records"] for item in sublist
            ]
            if api_out["data"]["authorities"][0] in ["arin"]:
                for record in flat_record_list:
                    if record["key"] == "ASName":
                        as_name = record["value"]
                        break
            elif api_out["data"]["authorities"][0] in ["afrinic", "apnic", "ripe"]:
                for record in flat_record_list:
                    if record["key"] == "as-name":
                        as_name = record["value"]
                        break
            elif api_out["data"]["authorities"][0] in ["lacnic"]:
                for record in flat_record_list:
                    if record["key"] == "owner":
                        as_name = record["value"]
                        break
            else:
                as_name = ""
        else:
            as_name = ""
    except:
        as_name = ""
    return as_name


async def ping_as(
    asn, sample_num, max_parallel, output_sample_num, verbose, random_seed
):
    try:
        announced_prefix_list = await get_announced_prefix(asn)
    except:
        json_msg = {"status": "fail", "message": "Fail to get prefix list"}
        typer.echo(json.dumps(json_msg))
        raise typer.Exit(code=1)

    reduced_prefix_list = reduce_prefix_list(announced_prefix_list, 24)

    reduced_prefix_list_len = len(reduced_prefix_list)
    if sample_num > reduced_prefix_list_len:
        sample_num = reduced_prefix_list_len

    random.seed(random_seed)
    sampled_prefix_list = random.sample(reduced_prefix_list, sample_num)

    analysis_out_list = await scan_prefix_list(
        sampled_prefix_list, max_parallel, random_seed
    )

    alive_prefix_count = 0
    dead_prefix_count = 0
    mix_as_path_avg_rrt_list = []
    per_as_path_avg_rrt_list = {}
    per_as_path_address_list = {}
    for analysis_out in analysis_out_list:
        if analysis_out["alive_addr_count"] == 0:
            dead_prefix_count += 1
        else:
            alive_prefix_count += 1
            as_path_str = "_".join(list(map(lambda x: str(x), analysis_out["as_path"])))
            if as_path_str not in per_as_path_avg_rrt_list:
                per_as_path_avg_rrt_list[as_path_str] = []
                per_as_path_address_list[as_path_str] = []
            mix_as_path_avg_rrt_list.append(analysis_out["avg_rrt"])
            per_as_path_avg_rrt_list[as_path_str].append(analysis_out["avg_rrt"])
            per_as_path_address_list[as_path_str].extend(
                list(analysis_out["alive_addr_set"])
            )
    if alive_prefix_count == 0:
        json_msg = {"status": "fail", "message": "No live prefix found in AS" + asn}
        typer.echo(json.dumps(json_msg))
        raise typer.Exit(code=1)

    mix_as_path_avg_rrt_list_len = len(mix_as_path_avg_rrt_list)
    per_as_path_avg_rrt = {}
    for as_path_str in per_as_path_avg_rrt_list:
        per_as_path_avg_rrt[as_path_str] = {}
        avg_rrt_list = per_as_path_avg_rrt_list[as_path_str]

        avg_rrt_list_len = len(avg_rrt_list)
        per_as_path_avg_rrt[as_path_str]["as_path_proportion"] = round(
            avg_rrt_list_len / mix_as_path_avg_rrt_list_len * 100, 2
        )

        sorted_avg_rrt_list = sorted(avg_rrt_list)
        per_as_path_avg_rrt[as_path_str]["as_avg_rrt"] = round(
            numpy.mean(avg_rrt_list), 2
        )
        per_as_path_avg_rrt[as_path_str]["as_rrt_sd"] = round(
            numpy.std(avg_rrt_list), 2
        )
        per_as_path_avg_rrt[as_path_str]["as_p10_rrt"] = sorted_avg_rrt_list[
            math.ceil(avg_rrt_list_len * 0.1) - 1
        ]
        per_as_path_avg_rrt[as_path_str]["as_p90_rrt"] = sorted_avg_rrt_list[
            math.ceil(avg_rrt_list_len * 0.9) - 1
        ]
        address_list_len = len(per_as_path_address_list[as_path_str])
        sample_num = round(
            output_sample_num * per_as_path_avg_rrt[as_path_str]["as_path_proportion"] / 100
        )
        if sample_num > address_list_len:
            sample_num = address_list_len
        per_as_path_avg_rrt[as_path_str]["sample_address"] = random.sample(
            per_as_path_address_list[as_path_str], sample_num
        )

    per_as_path_avg_rrt = dict(
        sorted(
            per_as_path_avg_rrt.items(),
            key=lambda x: x[1]["as_path_proportion"],
            reverse=True,
        )
    )

    as_name = await get_as_name(asn)

    json_msg = {
        "asn": asn,
        "as_name": as_name,
        "announced_prefix_count": reduced_prefix_list_len,
        "alive_prefix_count": alive_prefix_count,
        "dead_prefix_count": dead_prefix_count,
        "per_as_path_avg_rrt": per_as_path_avg_rrt,
    }
    if verbose:
        json_msg["prefix_result_list"] = analysis_out_list
    return json_msg


async def ping_as_list(
    asn_list, sample_num, max_parallel, output_sample_num, verbose, random_seed
):
    json_msg = {
        "random_seed": random_seed,
        "start_timestamp": int(time.time()),
        "end_timestamp": 0,
        "result_list": [],
    }
    for asn in asn_list:
        ping_out = await ping_as(
            asn, sample_num, max_parallel, output_sample_num, verbose, random_seed
        )
        json_msg["result_list"].append(ping_out)
    json_msg["end_timestamp"] = int(time.time())
    print(json.dumps(json_msg, indent=2))


async def get_country_top(country_code):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://stats.labs.apnic.net/aspop?f=j&c=" + country_code
            ) as response:
                api_out = await response.json()
        asn_list = []
        for ix in range(0, 7):
            if ix >= len(api_out["Data"]):
                break
            asn_list.append(api_out["Data"][ix]["AS"])
    except Exception as e:
        raise typer.Exit(code=1)
    return asn_list


def main(
    asn_list: List[int] = typer.Option([], "-a", "--asn", help="AS Number"),
    country_code: str = typer.Option("", "-c", "--country-code", help="Country Code"),
    sample_num: int = typer.Option(
        100, "-s", "--sample-num", help="Number of sample prefixes"
    ),
    max_parallel: int = typer.Option(
        25, "-p", "--max-parallel", help="Maximum parallel"
    ),
    output_sample_num: int = typer.Option(
        10,
        "-o",
        "--output-sample-num",
        help="The total number of output sample addresses",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose", help="Print detail information"
    ),
    random_seed: int = typer.Option(
        int(time.time()), "--random-seed", help="Random seed"
    ),
):
    loop = asyncio.get_event_loop()
    if country_code:
        asn_list = loop.run_until_complete(get_country_top(country_code))
    loop.run_until_complete(
        ping_as_list(
            asn_list, sample_num, max_parallel, output_sample_num, verbose, random_seed
        )
    )
    loop.close()


if __name__ == "__main__":
    typer.run(main)
