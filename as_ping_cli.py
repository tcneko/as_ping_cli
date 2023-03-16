#!/usr/bin/env python3

# author: tcneko <tcneko@outlook.com>
# start from: 2023.03
# last test environment: ubuntu 20.04
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


# function
async def fping(prefix: str):
    ip_network = ipaddress.ip_network(prefix)
    address_count = ip_network.num_addresses
    network_address = str(ip_network.network_address)
    broadcast_address = str(ip_network.broadcast_address)
    fping = await asyncio.create_subprocess_exec("fping", "-sq", "-c5", "-t1000", "-g", network_address, broadcast_address,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
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
    # alive_addr_set = set(alive_addr_list)
    # dead_addr_set = set(dead_addr_list)
    alive_count, dead_count, unknown_count = map(lambda x: int(
        x.strip().split(" ")[0]), fping_out_summary_list[-14:-11])
    min_rrt, avg_rrt, max_rrt = map(lambda x: float(
        x.strip().split(" ")[0]), fping_out_summary_list[-5:-2])
    json_msg = {"prefix": prefix, "alive_addr_count": alive_count, "dead_addr_count": dead_count,
                "min_rrt": min_rrt, "avg_rrt": avg_rrt, "max_rrt": max_rrt}
    return json_msg


async def scan_prefix_list(prefix_list: list, max_parallel: int):
    aio_task_list = []
    for prefix in prefix_list:
        semaphore = asyncio.Semaphore(max_parallel)

        async def sem_task(task):
            async with semaphore:
                return await task
        aio_task_list.append(sem_task(fping(prefix)))
    try:
        scan_out_list = await asyncio.gather(*aio_task_list)
    except Exception as e:
        for aio_task in aio_task_list:
            aio_task.cancel()
        json_msg = {"status": "fail",
                    "message": "Scan task fail"}
        typer.echo(json.dumps(json_msg))
        raise typer.Exit(code=1)
    return scan_out_list


async def get_announced_prefix(asn: int):
    announced_prefix_list = []
    async with aiohttp.ClientSession() as session:
        async with session.get("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + str(asn)) as response:
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


async def as_ping(asn, sample_num, max_parallel, verbose, random_seed):
    try:
        announced_prefix_list = await get_announced_prefix(asn)
    except:
        json_msg = {"status": "fail",
                    "message": "Fail to get prefix list"}
        typer.echo(json.dumps(json_msg))
        raise typer.Exit(code=1)

    reduced_prefix_list = reduce_prefix_list(announced_prefix_list, 24)

    reduced_prefix_list_len = len(reduced_prefix_list)
    if sample_num > reduced_prefix_list_len:
        sample_num = reduced_prefix_list_len

    random.seed(random_seed)
    sampled_prefix_list = random.sample(reduced_prefix_list, sample_num)

    scan_out_list = await scan_prefix_list(sampled_prefix_list, max_parallel)

    avg_rrt_list = []
    alive_prefix_count = 0
    dead_prefix_count = 0
    for scan_out in scan_out_list:
        if scan_out["alive_addr_count"] == 0:
            dead_prefix_count += 1
        else:
            alive_prefix_count += 1
            avg_rrt_list.append(scan_out["avg_rrt"])
    avg_rrt_list_len = len(avg_rrt_list)

    sorted_avg_rrt_list = sorted(avg_rrt_list)
    if avg_rrt_list_len != 0:
        as_avg_rrt = numpy.mean(avg_rrt_list)
        as_rrt_sd = numpy.std(avg_rrt_list)
        as_p50_rrt = sorted_avg_rrt_list[math.ceil(avg_rrt_list_len * 0.5)-1]
        as_p75_rrt = sorted_avg_rrt_list[math.ceil(avg_rrt_list_len * 0.75)-1]
        as_p90_rrt = sorted_avg_rrt_list[math.ceil(avg_rrt_list_len * 0.9)-1]
        as_p95_rrt = sorted_avg_rrt_list[math.ceil(avg_rrt_list_len * 0.95)-1]
    else:
        as_avg_rrt = 0
        as_rrt_sd = 0
        as_p50_rrt = 0
        as_p75_rrt = 0
        as_p90_rrt = 0
        as_p95_rrt = 0

    json_msg = {"asn": asn,
                "announced_prefix_count": reduced_prefix_list_len, "random_seed": random_seed, "sampled_prefix_count": sample_num,
                "alive_prefix_count": alive_prefix_count, "dead_prefix_count": dead_prefix_count,
                "as_avg_rrt": as_avg_rrt, "as_rrt_sd": as_rrt_sd,
                "as_p50_rrt": as_p50_rrt, "as_p75_rrt": as_p75_rrt, "as_p90_rrt": as_p90_rrt, "as_p95_rrt": as_p95_rrt}
    if verbose:
        json_msg["prefix_result_list"] = scan_out_list
    print(json.dumps(json_msg, indent=2))


def main(asn: int = typer.Option(..., "-a", "--asn", help="AS Number"),
         sample_num: int = typer.Option(
             50, "-s", "--sample", help="Number of sample prefixes"),
         max_parallel: int = typer.Option(
             20, "-p", "--max-parallel", help="Maximum parallel"),
         verbose: bool = typer.Option(
             False, "-v", "--verbose", help="Print detail information"),
         random_seed: int = typer.Option(
             int(time.time()), "--random-seed", help="Print detail information")):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        as_ping(asn, sample_num, max_parallel, verbose, random_seed))
    loop.close()


if __name__ == '__main__':
    typer.run(main)
