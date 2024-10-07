import pandas as pd
import json


class ExcelAdapter:

    def read_data(self, file, format):
        if format == "Polestar":
            return self.__read_polestar_data(file)
        else:
            return self.__read_zeekr_data(file)

    def __read_zeekr_data(self, file):
        return None

    def __read_polestar_data(self, file):
        data = pd.read_excel(file, sheet_name="TARA")
        data.ffill(inplace=True)
        data.bfill(inplace=True)
        asset_ids = data["Asset Id"].unique()
        assets = []
        for asset_id in asset_ids:
            asset_data = data[data["Asset Id"] == asset_id]

            asset_properties = asset_data["Security Properties"].unique()
            props = []
            for asset_property in asset_properties:
                property_data = asset_data[
                    asset_data["Security Properties"] == asset_property
                ]

                damage_data = property_data[
                    [
                        "Damage Scenario",
                        "Impact Type",
                        "Impact Rating",
                        "Argument",
                    ]
                ]

                damage_data = damage_data[
                    ~damage_data["Damage Scenario"].str.contains("N/A")
                ]
                damage = None
                if damage_data.shape[0] > 0:
                    damage = dict(
                        scenario=damage_data.iloc[0]["Damage Scenario"],
                        impact=damage_data.set_index("Impact Type")[
                            "Impact Rating"
                        ].to_dict(),
                        argument=damage_data.iloc[0]["Argument"],
                    )
                threat_data = property_data[
                    [
                        "Threat Scenario",
                        "Attack Path",
                        "Elapsed Time",
                        "Specialist Expertise",
                        "Knowledge of the item or component",
                        "Window of Opportunity",
                        "Equipment",
                        "Argument.1",
                        "Attack Vector",
                    ]
                ]

                threat_data = threat_data[
                    ~threat_data["Threat Scenario"].str.contains("N/A")
                ]
                threat = None
                if threat_data.shape[0] > 0:
                    threat = dict(
                        scenario=threat_data.iloc[0]["Threat Scenario"],
                        path=threat_data.iloc[0]["Attack Path"],
                        time=int(threat_data.iloc[0]["Elapsed Time"]),
                        expertise=int(threat_data.iloc[0]["Specialist Expertise"]),
                        knowledge=int(
                            threat_data.iloc[0]["Knowledge of the item or component"]
                        ),
                        window=int(threat_data.iloc[0]["Window of Opportunity"]),
                        equipment=int(threat_data.iloc[0]["Equipment"]),
                        argument=threat_data.iloc[0]["Argument.1"],
                        vector=threat_data.iloc[0]["Attack Vector"],
                    )
                    risk_data = property_data[
                        [
                            "Risk Treatment",
                            "Security Goal",
                            "Security Claim",
                            "CS concept",
                            "Elapsed Time.1",
                            "Specialist Expertise.1",
                            "Knowledge of the item or component.1",
                            "Window of Opportunity.1",
                            "Equipment.1",
                            "Argument.2",
                        ]
                    ]
                    risk = None
                    if risk_data.shape[0] > 0:
                        risk = dict(
                            treatment=risk_data.iloc[0]["Risk Treatment"],
                            goal=risk_data.iloc[0]["Security Goal"],
                            claim=risk_data.iloc[0]["Security Claim"],
                        )
                        requirement = None
                        requirement_data = risk_data[
                            [
                                "CS concept",
                                "Elapsed Time.1",
                                "Specialist Expertise.1",
                                "Knowledge of the item or component.1",
                                "Window of Opportunity.1",
                                "Equipment.1",
                                "Argument.2",
                            ]
                        ]
                        if requirement_data.shape[0] > 0:
                            requirement = dict(
                                control=risk_data.iloc[0]["CS concept"],
                                time=int(risk_data.iloc[0]["Elapsed Time.1"]),
                                expertise=int(
                                    risk_data.iloc[0]["Specialist Expertise.1"]
                                ),
                                knowledge=int(
                                    risk_data.iloc[0][
                                        "Knowledge of the item or component.1"
                                    ]
                                ),
                                window=int(
                                    risk_data.iloc[0]["Window of Opportunity.1"]
                                ),
                                equipment=int(risk_data.iloc[0]["Equipment.1"]),
                                argument=risk_data.iloc[0]["Argument.2"],
                            )

                        risk["requirement"] = requirement

                    threat["risk"] = risk

                prop = dict(name=asset_property, damage=damage, threat=threat)
                props.append(prop)
            asset = dict(
                id=int(asset_id),
                name=asset_data.iloc[0]["Asset"],
                security_properties=props,
                attack_vector=asset_data.iloc[0]["Attack Vector"],
                CAL=asset_data.iloc[0]["CAL"],
            )
            assets.append(asset)
        """ with open("data.json", "w") as file:
            json.dump({"assets": assets}, file, indent=4) """
        return {"assets": assets}
