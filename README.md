# Implementations of NA-GTA-MAC
This is the implementation of non-adaptive group-testing aggregate message authentication code scheme (NA-GTA-MAC) which was proposed by Hirose and Shikata at ISPEC 2018.
In addition, I implement the aggregate message authentication code scheme(A-MAC) which was introduced by Katz-Lindell at CT-RSA 2008.

## Usage
### configuration
d is the maximum number of tampering which NA-GTA-MAC can detect.
The value of d can be changed by changing value of d in the source code of NA-GTA-MAC.

### execution
```
$ python3 NA_GTA_MAC/xxxxxxxx.py
```
note: xxxxxxxx.py is one of the following files.
|  File name  | Summary |
| ---- | ---- |
|  based_on_katz_lindell_na_gta_mac_naive.py    | Naive Method of NA-GTA-MAC based on Katz-Lindell Aggregate MAC  |
|  based_on_katz_lindell_na_gta_mac_generic.py  |  Improvement for Generic way of Generating matrices of NA-GTA-MAC based on Katz-Lindell Aggregate MAC |
|  based_on_katz_lindell_na_gta_mac_specific.py |  Improvement for a Specific way of Generating matrices of NA-GTA-MAC based on Katz-Lindell Aggregate MAC |
|  hashing_na_gta_mac_naive.py                  |  Naive Method of NA-GTA-MAC Scheme Using Hashing for Aggregate  |


## Reference
- https://eprint.iacr.org/2018/448.pdf
- https://www.cs.umd.edu/~jkatz/papers/aggregateMAC.pdf