import json
import numpy as np
import pandas as pd
from pandas import json_normalize
from enum import Enum


class ManalyzeDetectionReason(Enum):
    UNUSUAL_SECTION_NAME = 1
    W_AND_X = 2
    FEW_IMPORTS = 3
    KNOWN_SECTION_NAME = 4
    BROKEN_RITCH_HEADER = 5
    BROKEN_RESOURCE = 6

    @staticmethod
    def has_unusual_section_name(msg):
        return ("Unusual section name found:" in msg)

    @staticmethod
    def has_w_and_x_section(msg):
        return ("is both writable and executable." in msg)

    @staticmethod
    def has_few_imports(msg):
        return ("The PE only has" in msg)

    @staticmethod
    def has_known_section_name(msg):
        return ("The PE is packed with" in msg)\
            or ("This PE is packed with" in msg)\
            or ("This PE is a" in msg)

    @staticmethod
    def has_broken_rich_header(msg):
        return ("The RICH header checksum is invalid." in msg)\
            or ("The number of imports reported in the RICH header is inconsistent." in msg)

    @staticmethod
    def has_broken_resource(msg):
        return "The PE's resources are bigger than it is." in msg

    @staticmethod
    def msg_to_enum(msg):
        if ManalyzeDetectionReason.has_unusual_section_name(msg):
            return ManalyzeDetectionReason.UNUSUAL_SECTION_NAME
        # elif ManalyzeDetectionReason.has_w_and_x_section(msg):
        #    return ManalyzeDetectionReason.W_AND_X
        # elif ManalyzeDetectionReason.has_few_imports(msg):
        #     return ManalyzeDetectionReason.FEW_IMPORTS
        elif ManalyzeDetectionReason.has_known_section_name(msg):
            return ManalyzeDetectionReason.KNOWN_SECTION_NAME
        elif ManalyzeDetectionReason.has_broken_resource(msg):
            return ManalyzeDetectionReason.BROKEN_RESOURCE
        elif ManalyzeDetectionReason.has_broken_rich_header(msg):
            return ManalyzeDetectionReason.BROKEN_RITCH_HEADER
        else:
            return None


class PyPackerDetectionReason(Enum):
    TOO_FEW_IMPORTS = 1
    NONSTANDARD_SECTIONNAME = 2
    SECTION_NAME_IS_KNOWN = 3
    BAD_ENTRY_POINT = 4
    @staticmethod
    def has_bad_entry_point(msg):
        return ("Null entry point" in msg)\
            or ("doesn't fall in valid section" in msg)\
            or ("falls in overlapping sections:" in msg)\
            or ("in irregular section(s):" in msg)

    @staticmethod
    def has_lowimport(msg):
        return "Too few imports" in msg

    @staticmethod
    def has_nonstandard_section_name(msg):
        return ("Section name with invalid characters" in msg)\
            or ("non-standard sections:" in msg)\
            or ("sections with invalid names" in msg)

    @staticmethod
    def has_known_section_name(msg):
        return "matches known packer:" in msg

    @staticmethod
    def msg_to_enum(msg):
        if PyPackerDetectionReason.has_bad_entry_point(msg):
            return PyPackerDetectionReason.BAD_ENTRY_POINT
        # elif PyPackerDetectionReason.has_lowimport(msg):
        #     return PyPackerDetectionReason.TOO_FEW_IMPORTS
        elif PyPackerDetectionReason.has_nonstandard_section_name(msg):
            return PyPackerDetectionReason.NONSTANDARD_SECTIONNAME
        elif PyPackerDetectionReason.has_known_section_name(msg):
            return PyPackerDetectionReason.SECTION_NAME_IS_KNOWN
        else:
            return None


def process_manalyze_result(l):
    if l["result"]:
        result_level = l["result"]["level"]
        result_output = list(l["result"]["plugin_output"].values())
    else:
        result_level = None
        result_output = None
    return {
        "name": l["name"],
        "manalyze_result_level": result_level,
        "manalyze_result_output": result_output
    }


def process_peid(l):
    return {
        "name": l["name"],
        "peid_packed": l["Packed"] == "yes",
        "peid_PEiD": l["PEiD"]
    }


def process_pypacker(l):
    return {
        "name": l["name"],
        "pypacker_suspicions": l["feature_suspicions"],
        "pypacker_detections": l["feature_detections"]
    }


def load_nested_json(fname: str, process):
    with open(fname, "r") as fin:
        dat = json_normalize(process(json.loads(l)) for l in fin)
    return dat


