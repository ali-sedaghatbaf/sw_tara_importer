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
        risk_treatment_options = {
            "Avoiding": "Avoidance",
            "Retaining": "Retention",
            "Sharing": "Sharing",
            "Reducing": "Reduction",
        }

        data = pd.read_excel(file, sheet_name="TARA")
        data.loc[:, data.columns != "Impact Rating"] = data.loc[
            :, data.columns != "Impact Rating"
        ].ffill()
        data.loc[:, data.columns != "Impact Rating"] = data.loc[
            :, data.columns != "Impact Rating"
        ].bfill()
        asset_ids = data["Asset Id"].astype(int).unique()
        assets = []
        for asset_id in asset_ids:
            asset_data = data[data["Asset Id"] == asset_id]
            asset_name = asset_data.iloc[0]["Asset"]
            asset_properties = asset_data["Security Properties"].unique()
            props = []
            for asset_property in asset_properties:
                property_data = asset_data[
                    asset_data["Security Properties"] == asset_property.strip()
                ]

                damage_data = property_data[
                    [
                        "Damage Scenario",
                        "Impact Type",
                        "Impact Rating",
                        "Argument",
                    ]
                ]

                damage = None
                nondamage = None
                if damage_data.shape[0] > 0:
                    damage_data = damage_data.fillna("")
                    if "N/A" in damage_data.iloc[0]["Damage Scenario"]:
                        nondamage = dict(
                            id=f"Non-Damage Scenario for {asset_property} of Asset {asset_id}",
                            scenario=damage_data.iloc[0]["Damage Scenario"],
                            argument=damage_data.iloc[0]["Argument"],
                        )
                    else:
                        damage = dict(
                            id=f"Damage Scenario for {asset_property} of Asset {asset_id}",
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
                    first_row = threat_data.iloc[0]

                    threat = dict(
                        id=f"Threat Scenario for {asset_property} of Asset {asset_id}",
                        scenario=first_row["Threat Scenario"],
                        path=first_row["Attack Path"],
                        time=(
                            int(first_row["Elapsed Time"])
                            if pd.notna(first_row["Elapsed Time"])
                            else None
                        ),
                        expertise=(
                            int(first_row["Specialist Expertise"])
                            if pd.notna(first_row["Specialist Expertise"])
                            else None
                        ),
                        knowledge=(
                            int(first_row["Knowledge of the item or component"])
                            if pd.notna(first_row["Knowledge of the item or component"])
                            else None
                        ),
                        window=(
                            int(first_row["Window of Opportunity"])
                            if pd.notna(first_row["Window of Opportunity"])
                            else None
                        ),
                        equipment=(
                            int(first_row["Equipment"])
                            if pd.notna(first_row["Equipment"])
                            else None
                        ),
                        argument=first_row["Argument.1"],
                        vector=first_row["Attack Vector"],
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
                        first_row = risk_data.iloc[0]

                        risk = dict(
                            treatment=risk_treatment_options[
                                first_row["Risk Treatment"].strip()
                            ],
                            goal=dict(
                                id=f"Cybersecurity Goal for {asset_property} of Asset {asset_id}",
                                description=first_row["Security Goal"],
                            ),
                            claim=dict(
                                id=f"Cybersecurity Claim for {asset_property} of Asset {asset_id}",
                                description=first_row["Security Claim"],
                            ),
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
                                id=f"Cybersecurity Requirement for {asset_property} of Asset {asset_id}",
                                control=first_row["CS concept"],
                                time=(
                                    int(first_row["Elapsed Time.1"])
                                    if pd.notna(first_row["Elapsed Time.1"])
                                    else None
                                ),
                                expertise=(
                                    int(first_row["Specialist Expertise.1"])
                                    if pd.notna(first_row["Specialist Expertise.1"])
                                    else None
                                ),
                                knowledge=(
                                    int(
                                        first_row[
                                            "Knowledge of the item or component.1"
                                        ]
                                    )
                                    if pd.notna(
                                        first_row[
                                            "Knowledge of the item or component.1"
                                        ]
                                    )
                                    else None
                                ),
                                window=(
                                    int(first_row["Window of Opportunity.1"])
                                    if pd.notna(first_row["Window of Opportunity.1"])
                                    else None
                                ),
                                equipment=(
                                    int(first_row["Equipment.1"])
                                    if pd.notna(first_row["Equipment.1"])
                                    else None
                                ),
                                argument=first_row["Argument.2"],
                            )

                        risk["requirement"] = requirement

                    threat["risk"] = risk

                prop = dict(
                    name=asset_property,
                    damage=damage,
                    nondamage=nondamage,
                    threat=threat,
                )
                props.append(prop)

            asset = dict(
                id=int(asset_id),
                name=asset_name,
                security_properties=props,
                attack_vector=asset_data.iloc[0]["Attack Vector"],
                CAL=asset_data.iloc[0]["CAL"],
            )
            assets.append(asset)
        # with open("data.json", "w") as file:
        #    json.dump({"assets": assets}, file, indent=4)
        return {"assets": assets}
