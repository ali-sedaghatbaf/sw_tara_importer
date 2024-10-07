import clr

clr.AddReference("SystemWeaverClientAPI")

from SystemWeaverAPI import *
from SystemWeaver.Common import *
import pandas as pd


class SWAdapter:
    def __init__(self, server, port) -> None:
        self.server = server
        self.port = port
        self.item_choice = "Create"

    def authenticate(self, auth_data):

        SWConnection.Instance.LoginName = auth_data["username"]
        SWConnection.Instance.Password = auth_data["password"]
        SWConnection.Instance.ServerMachineName = self.server
        SWConnection.Instance.ServerPort = self.port
        """ SWConnection.Instance.AuthenticationMethod = (
            AuthenticationMethod.NetworkAuthentication
        ) """

        SWConnection.Instance.Login(getattr(EventSynchronization, "None"))

    def write_data(self, data, sids):

        self.cslib = data["cslib_handle"]
        item_sids = sids[["Item Type", "Item SID"]]
        part_sids = sids[["Part Type", "Part SID"]]
        attr_sids = sids[["Attribute Type", "Attribute SID"]]
        if SWConnection.Instance.Connected:
            cs_item = self.__get_item_by_handle(data["cs_handle"])

            tara_item = self.__create_or_get_item(
                cs_item,
                data["tara_name"],
                item_sids[item_sids["Item Type"] == "TARA"]["Item SID"].iloc[0],
                part_sids[part_sids["Part Type"] == "Threat Analysis Area"][
                    "Part SID"
                ].iloc[0],
            )
            sys_model_item = self.__create_or_get_item(
                tara_item,
                "System Model",
                item_sids[item_sids["Item Type"] == "Conceptual Architecture"][
                    "Item SID"
                ].iloc[0],
                part_sids[part_sids["Part Type"] == "Security Item Definition"][
                    "Part SID"
                ].iloc[0],
            )
            cs_properties_item = self.__create_or_get_item(
                tara_item,
                "Cybersecurity Properties",
                item_sids[item_sids["Item Type"] == "Security Property Catalog"][
                    "Item SID"
                ].iloc[0],
                part_sids[part_sids["Part Type"] == "Security Property List"][
                    "Part SID"
                ].iloc[0],
            )
            cs_property_items = {}
            if "assets" in data:
                for asset in data["assets"]:
                    asset_item = self.__create_or_get_item(
                        sys_model_item,
                        asset["name"],
                        item_sids[
                            item_sids["Item Type"] == "Conceptual System/Component"
                        ]["Item SID"].iloc[0],
                        part_sids[
                            part_sids["Part Type"] == "Included System/Component"
                        ]["Part SID"].iloc[0],
                    )
                    for default_attr in asset_item.swItemType.GetAllDefaultAttributes():
                        attrObj = IswDefaultAttribute(default_attr).AttrType
                        if attrObj.DataType.ToString().lower() != "computed":
                            dynType = self.__get_attrtype_by_handle(attrObj.HandleStr)
                            attr = asset_item.GetOrMakeAttributeOfType(dynType)
                            if attr.AttributeType.SID == "SA0072":  # foreign id
                                attr.ValueAsString = asset["id"]
                    self.__add_item(tara_item, asset_item, "SP0261")
                    for cs_property in asset["security_properties"]:
                        cs_property_name = cs_property["name"]
                        cs_property_item = cs_property_items.get(cs_property_name)
                        if not cs_property_item:
                            cs_property_item = self.__create_or_get_item(
                                cs_properties_item,
                                cs_property["name"],
                                item_sids[
                                    item_sids["Item Type"] == "Security Property"
                                ]["Item SID"].iloc[0],
                                part_sids[
                                    part_sids["Part Type"] == "Security Property"
                                ]["Part SID"].iloc[0],
                            )
                            cs_property_items[cs_property_name] = cs_property_item
                        damage = cs_property["damage"]
                        if damage:
                            damage_item = self.__create_or_get_item(
                                tara_item,
                                damage["scenario"],
                                item_sids[item_sids["Item Type"] == "Damage Scenario"][
                                    "Item SID"
                                ].iloc[0],
                                part_sids[part_sids["Part Type"] == "Damage Scenario"][
                                    "Part SID"
                                ].iloc[0],
                            )
                            self.__add_item(
                                damage_item,
                                asset_item,
                                part_sids[part_sids["Part Type"] == "Analyzed Asset"][
                                    "Part SID"
                                ].iloc[0],
                            )
                            self.__add_item(
                                damage_item,
                                cs_property_item,
                                part_sids[
                                    part_sids["Part Type"]
                                    == "Violates Security Property"
                                ]["Part SID"].iloc[0],
                            )

                            impact = damage["impact"]
                            for (
                                default_attr
                            ) in damage_item.swItemType.GetAllDefaultAttributes():
                                attrObj = IswDefaultAttribute(default_attr).AttrType
                                if attrObj.DataType.ToString().lower() != "computed":
                                    dynType = self.__get_attrtype_by_handle(
                                        attrObj.HandleStr
                                    )
                                    attr = damage_item.GetOrMakeAttributeOfType(dynType)
                                    if (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Safety Impact"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # safety impact
                                        attr.ValueAsString = impact["S"]
                                    elif (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Privacy Impact"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # privacy impact
                                        attr.ValueAsString = impact["P"]
                                    elif (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Financial Impact"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # finncial impact
                                        attr.ValueAsString = impact["F"]
                                    elif (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Operational Impact"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # operational impact
                                        attr.ValueAsString = impact["O"]
                                    elif (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Damage Argument"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # argument
                                        attr.ValueAsString = damage["argument"]
                                    elif (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Damage Scenario"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # argument
                                        attr.ValueAsString = damage["scenario"]
                        threat = cs_property["threat"]
                        if threat:
                            risk = threat["risk"]
                            threat_item = self.__create_or_get_item(
                                tara_item,
                                threat["scenario"],
                                item_sids[item_sids["Item Type"] == "Threat Scenario"][
                                    "Item SID"
                                ].iloc[0],
                                part_sids[part_sids["Part Type"] == "Threat Scenario"][
                                    "Part SID"
                                ].iloc[0],
                            )
                            if damage:
                                self.__add_item(
                                    threat_item,
                                    damage_item,
                                    part_sids[
                                        part_sids["Part Type"]
                                        == "Leads to Damage Scenario"
                                    ]["Part SID"].iloc[0],
                                )
                            for (
                                default_attr
                            ) in threat_item.swItemType.GetAllDefaultAttributes():
                                attrObj = IswDefaultAttribute(default_attr).AttrType
                                if attrObj.DataType.ToString().lower() != "computed":
                                    dynType = self.__get_attrtype_by_handle(
                                        attrObj.HandleStr
                                    )
                                    attr = threat_item.GetOrMakeAttributeOfType(dynType)
                                    if (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Threat Argument"
                                        ]["Attribute SID"].iloc[0]
                                    ):
                                        attr.ValueAsString = threat["argument"]
                                    elif (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"]
                                            == "Risk Treatment"
                                        ]["Attribute SID"].iloc[0]
                                        and risk
                                    ):
                                        attr.ValueAsString = risk["treatment"]

                            vector_item = self.__create_or_get_item(
                                threat_item,
                                "Attack Vector",
                                item_sids[item_sids["Item Type"] == "Attack Vector"][
                                    "Item SID"
                                ].iloc[0],
                                part_sids[part_sids["Part Type"] == "Attack Vector"][
                                    "Part SID"
                                ].iloc[0],
                            )
                            for (
                                default_attr
                            ) in vector_item.swItemType.GetAllDefaultAttributes():
                                attrObj = IswDefaultAttribute(default_attr).AttrType
                                if attrObj.DataType.ToString().lower() != "computed":
                                    dynType = self.__get_attrtype_by_handle(
                                        attrObj.HandleStr
                                    )
                                    attr = vector_item.GetOrMakeAttributeOfType(dynType)
                                    if (
                                        attr.AttributeType.SID
                                        == attr_sids[
                                            attr_sids["Attribute Type"] == "Vector Type"
                                        ]["Attribute SID"].iloc[0]
                                    ):  # vector type
                                        attr.ValueAsString = threat["vector"]
                            attack_path = threat["path"]
                            attack_steps = attack_path.split("\n")
                            attack_step_items = []
                            if len(attack_steps) == 1:
                                attack_step_items.append(
                                    self.__create_or_get_item(
                                        threat_item,
                                        attack_path,
                                        item_sids[
                                            item_sids["Item Type"] == "Attack Step"
                                        ]["Item SID"].iloc[0],
                                        part_sids[
                                            part_sids["Part Type"] == "Attack Step"
                                        ]["Part SID"].iloc[0],
                                    )
                                )
                            else:
                                attack_and_item = self.__create_or_get_item(
                                    threat_item,
                                    "AND",
                                    item_sids[item_sids["Item Type"] == "Attack And"][
                                        "Item SID"
                                    ].iloc[0],
                                    part_sids[part_sids["Part Type"] == "Attack And"][
                                        "Part SID"
                                    ].iloc[0],
                                )
                                for attack_step in attack_steps:
                                    attack_step_items.append(
                                        self.__create_or_get_item(
                                            attack_and_item,
                                            attack_step,
                                            item_sids[
                                                item_sids["Item Type"] == "Attack Step"
                                            ]["Item SID"].iloc[0],
                                            part_sids[
                                                part_sids["Part Type"] == "Attack Step"
                                            ]["Part SID"].iloc[0],
                                        )
                                    )

                            for attack_step_item in attack_step_items:

                                for (
                                    default_attr
                                ) in (
                                    attack_step_item.swItemType.GetAllDefaultAttributes()
                                ):
                                    attrObj = IswDefaultAttribute(default_attr).AttrType
                                    if (
                                        attrObj.DataType.ToString().lower()
                                        != "computed"
                                    ):
                                        dynType = self.__get_attrtype_by_handle(
                                            attrObj.HandleStr
                                        )
                                        attr = (
                                            attack_step_item.GetOrMakeAttributeOfType(
                                                dynType
                                            )
                                        )

                                        if (
                                            attr.AttributeType.SID
                                            == attr_sids[
                                                attr_sids["Attribute Type"]
                                                == "Elapsed Time"
                                            ]["Attribute SID"].iloc[0]
                                        ):
                                            attr.ValueAsString = str(threat["time"])
                                        elif (
                                            attr.AttributeType.SID
                                            == attr_sids[
                                                attr_sids["Attribute Type"]
                                                == "Specialist Expertise"
                                            ]["Attribute SID"].iloc[0]
                                        ):
                                            attr.ValueAsString = str(
                                                threat["expertise"]
                                            )
                                        elif (
                                            attr.AttributeType.SID
                                            == attr_sids[
                                                attr_sids["Attribute Type"]
                                                == "Attack Knowledge"
                                            ]["Attribute SID"].iloc[0]
                                        ):
                                            attr.ValueAsString = str(
                                                threat["knowledge"]
                                            )
                                        elif (
                                            attr.AttributeType.SID
                                            == attr_sids[
                                                attr_sids["Attribute Type"]
                                                == "Window of Opportunity"
                                            ]["Attribute SID"].iloc[0]
                                        ):
                                            attr.ValueAsString = str(threat["window"])
                                        elif (
                                            attr.AttributeType.SID
                                            == attr_sids[
                                                attr_sids["Attribute Type"]
                                                == "Equipment"
                                            ]["Attribute SID"].iloc[0]
                                        ):
                                            attr.ValueAsString = str(
                                                threat["equipment"]
                                            )
                                        elif (
                                            attr.AttributeType.SID
                                            == attr_sids[
                                                attr_sids["Attribute Type"]
                                                == "Attack Step Argument"
                                            ]["Attribute SID"].iloc[0]
                                        ):
                                            attr.ValueAsString = threat["argument"]

                            if risk["goal"]:
                                goal_item = self.__create_or_get_item(
                                    tara_item,
                                    risk["goal"],
                                    item_sids[
                                        item_sids["Item Type"] == "Security Goal"
                                    ]["Item SID"].iloc[0],
                                    part_sids[
                                        part_sids["Part Type"] == "Security Goal"
                                    ]["Part SID"].iloc[0],
                                )
                                self.__add_item(
                                    goal_item,
                                    threat_item,
                                    part_sids[
                                        part_sids["Part Type"] == "On Threat Scenario"
                                    ]["Part SID"].iloc[0],
                                )
                                if risk["requirement"]:
                                    requirement = risk["requirement"]
                                    requirement_item = self.__create_or_get_item(
                                        goal_item,
                                        requirement["control"],
                                        item_sids[
                                            item_sids["Item Type"]
                                            == "Security Requirement"
                                        ]["Item SID"].iloc[0],
                                        part_sids[
                                            part_sids["Part Type"]
                                            == "Security Requirement"
                                        ]["Part SID"].iloc[0],
                                    )
                                    for (
                                        default_attr
                                    ) in (
                                        requirement_item.swItemType.GetAllDefaultAttributes()
                                    ):
                                        attrObj = IswDefaultAttribute(
                                            default_attr
                                        ).AttrType
                                        if (
                                            attrObj.DataType.ToString().lower()
                                            != "computed"
                                        ):
                                            dynType = self.__get_attrtype_by_handle(
                                                attrObj.HandleStr
                                            )
                                            attr = requirement_item.GetOrMakeAttributeOfType(
                                                dynType
                                            )

                                            if (
                                                attr.AttributeType.SID
                                                == attr_sids[
                                                    attr_sids["Attribute Type"]
                                                    == "Elapsed Time"
                                                ]["Attribute SID"].iloc[0]
                                            ):
                                                attr.ValueAsString = str(threat["time"])
                                            elif (
                                                attr.AttributeType.SID
                                                == attr_sids[
                                                    attr_sids["Attribute Type"]
                                                    == "Specialist Expertise"
                                                ]["Attribute SID"].iloc[0]
                                            ):
                                                attr.ValueAsString = str(
                                                    threat["expertise"]
                                                )
                                            elif (
                                                attr.AttributeType.SID
                                                == attr_sids[
                                                    attr_sids["Attribute Type"]
                                                    == "Attack Knowledge"
                                                ]["Attribute SID"].iloc[0]
                                            ):
                                                attr.ValueAsString = str(
                                                    threat["knowledge"]
                                                )
                                            elif (
                                                attr.AttributeType.SID
                                                == attr_sids[
                                                    attr_sids["Attribute Type"]
                                                    == "Window of Opportunity"
                                                ]["Attribute SID"].iloc[0]
                                            ):
                                                attr.ValueAsString = str(
                                                    threat["window"]
                                                )
                                            elif (
                                                attr.AttributeType.SID
                                                == attr_sids[
                                                    attr_sids["Attribute Type"]
                                                    == "Equipment"
                                                ]["Attribute SID"].iloc[0]
                                            ):
                                                attr.ValueAsString = str(
                                                    threat["equipment"]
                                                )

                            if risk["claim"]:
                                claim_item = self.__create_or_get_item(
                                    tara_item,
                                    risk["claim"],
                                    item_sids[
                                        item_sids["Item Type"] == "Security Claim"
                                    ]["Item SID"].iloc[0],
                                    part_sids[
                                        part_sids["Part Type"] == "Security Claim"
                                    ]["Part SID"].iloc[0],
                                )
                                self.__add_item(
                                    claim_item,
                                    threat_item,
                                    part_sids[
                                        part_sids["Part Type"] == "On Threat Scenario"
                                    ]["Part SID"].iloc[0],
                                )

    def __get_attrtype_by_handle(self, attr_handle):
        handle = SWHandleUtility.ToHandle(attr_handle)
        return SWConnection.Instance.Broker.GetAttributeType(handle)

    def __get_item_by_handle(self, item_handle):
        handle = SWHandleUtility.ToHandle(item_handle)
        return SWConnection.Instance.Broker.GetItem(handle)

    def __add_item(self, p_item, item, part_SID):
        parent_item = IswItem(p_item)
        existing_items = [
            IswPart(part).DefObj for part in parent_item.GetParts(part_SID)
        ]
        if item in existing_items:
            return
        part_type = p_item.Broker.FindPartTypeWithSID(part_SID)
        if part_type.Multiplicity == SWMultiplicity.Single:
            p_item.SetPartObj(part_SID, item)
        else:
            p_item.AddPart(part_SID, item)

    def __create_or_get_item(self, p_item, item_name, item_SID, part_SID):
        parent_item = IswItem(p_item)
        cyberLib = SWConnection.Instance.Broker.GetLibrary(
            SWHandleUtility.ToHandle(self.cslib)
        )

        item = cyberLib.CreateItem(item_SID, item_name)

        part_type = p_item.Broker.FindPartTypeWithSID(part_SID)
        if part_type.Multiplicity == SWMultiplicity.Single:
            parent_item.SetPartObj(part_SID, item)
        else:
            parent_item.AddPart(part_SID, item)
        return IswItem(item)

    def __find_items_with_part_type(self, p_item, part_sid):
        parts = p_item.GetParts(part_sid)
        return [IswPart(part).DefObj for part in parts if parts]
