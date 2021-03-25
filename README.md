# Evaluation of packer detection tool for FFRI Dataset scripts

## About this repository

In order to resolve [the issue of FFRI Dataset scripts](https://github.com/FFRI/ffridataset-scripts/issues/1), we evaluated some existing OSS packer detection tools.

In this repository, we compare the performance of tools that provide heuristic packer detections (e.g., few import APIs, existence of sections with high entropy, broken rich header, ...).

Note that we previously published similar repository [PackerDetectionToolEvaluation](https://github.com/FFRI/PackerDetectionToolEvaluation), but it focused on the evaluation of signature-based packer detection tools.

## Targets

- [PyPackerDetect](https://github.com/cylance/PyPackerDetect)
- [Manalyze](https://github.com/JusticeRage/Manalyze)
- [pypeid](https://github.com/FFRI/pypeid)

## Dataset

We use [PackingData](https://github.com/chesvectain/PackingData) dataset for this evaluation.

Note that we fixed [the issue of PackingData](https://github.com/FFRI/PackerDetectionToolEvaluation#packingdata) for this evaluation.

## Result

TPR is almost the same between PyPacker and Manalyze; its value is about 94%.
The performance of pypeid is slightly lower than these two tools.

On the other hand, FPR was much lower when using PyPacker or pypeid compared with Manalyze.

|   | TPR  | FPR  |
|:-:|:-:|:-:|
| PyPackerDetect | 94.6% | 2.2% |
| Manalyze | 95.0% | 41.0% |
| pypeid | 84.9% | 5.6%|

See [Jupyter Notebook](./analyze_packing_data.ipynb) for more details.

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2020

## License

[Apache version 2.0](./LICENSE)
