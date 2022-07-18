# Usage

## http_zipf_packet.py

> need 'numpy' and 'requests' module, if not installed, please install them first.

```shell
python3 http_zipf_packets.py -i <ip> -f <number of flows> -p <number of packets> -e <exponent float> -u <uri_list path>
```
- `-i <ip/domain_name>` example: `-i 2400:dd01::1` or `-i www.baidu.com`

- `-f <number of flows>` example: `-f 3`, which means create three flows with different uri in the uri_list.

- `-p <number of packets>` example: `-p 100`, which means A total of 100 http requests are generated.

- `-e <exponent float>` example: `-e 2`, this is the parameter of zipf distribution (P(X) = C * X^(-e))

- `-u <uri_list path>` example: `-u ./test.cfg`, Offer the config file path of the uri_list only when you want to use self-defined uri-list.

>Example usage: python3 http_zipf_packets.py -i www.baidu.com -f 3 -p 20 -e 2 -u uri_list.cfg

>Note: A tail heavy distribution correlates with the increase of the exponent.
