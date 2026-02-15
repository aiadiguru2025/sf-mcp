"""Data center mappings, constants, and defaults for SuccessFactors API."""

# OData defaults
DEFAULT_TIMEOUT = 30
DEFAULT_FORMAT = "json"
DEFAULT_TOP = 100
MAX_TOP_STANDARD = 500
MAX_TOP_QUERY = 1000
MAX_TOP_SEARCH = 200

# Validation limits
MAX_FILTER_LENGTH = 2000

# =============================================================================
# Data Center to API Host Mapping (from SAP official documentation)
# =============================================================================
# Format: {(data_center, environment): api_host}

DC_API_HOST_MAP = {
    # DC10 / DC66 - Sydney, Australia (Azure)
    ("DC10", "production"): "api10.successfactors.com",
    ("DC10", "preview"): "api10preview.sapsf.com",
    ("DC66", "production"): "api10.successfactors.com",
    ("DC66", "preview"): "api10preview.sapsf.com",

    # DC12 / DC33 - Rot, Germany
    ("DC12", "production"): "api012.successfactors.eu",
    ("DC12", "preview"): "api12preview.sapsf.eu",
    ("DC33", "production"): "api012.successfactors.eu",
    ("DC33", "preview"): "api12preview.sapsf.eu",

    # DC15 / DC30 - Shanghai, China
    ("DC15", "production"): "api15.sapsf.cn",
    ("DC15", "preview"): "api15preview.sapsf.cn",
    ("DC30", "production"): "api15.sapsf.cn",
    ("DC30", "preview"): "api15preview.sapsf.cn",

    # DC17 / DC60 - Toronto, Canada (Azure)
    ("DC17", "production"): "api17.sapsf.com",
    ("DC17", "preview"): "api17preview.sapsf.com",
    ("DC60", "production"): "api17.sapsf.com",
    ("DC60", "preview"): "api17preview.sapsf.com",

    # DC19 / DC62 - Sao Paulo, Brazil (Azure)
    ("DC19", "production"): "api19.sapsf.com",
    ("DC19", "preview"): "api19preview.sapsf.com",
    ("DC62", "production"): "api19.sapsf.com",
    ("DC62", "preview"): "api19preview.sapsf.com",

    # DC2 / DC57 - Eemshaven, Netherlands (GCP)
    ("DC2", "production"): "api2.successfactors.eu",
    ("DC2", "preview"): "api2preview.sapsf.eu",
    ("DC2", "sales_demo"): "apisalesdemo2.successfactors.eu",
    ("DC57", "production"): "api2.successfactors.eu",
    ("DC57", "preview"): "api2preview.sapsf.eu",
    ("DC57", "sales_demo"): "apisalesdemo2.successfactors.eu",

    # DC22 - Dubai, UAE
    ("DC22", "production"): "api22.sapsf.com",
    ("DC22", "preview"): "api22preview.sapsf.com",

    # DC23 / DC84 - Riyadh, Saudi Arabia
    ("DC23", "production"): "api23.sapsf.com",
    ("DC23", "preview"): "api23preview.sapsf.com",
    ("DC84", "production"): "api23.sapsf.com",
    ("DC84", "preview"): "api23preview.sapsf.com",

    # DC4 / DC68 - Virginia, US (Azure)
    ("DC4", "production"): "api4.successfactors.com",
    ("DC4", "preview"): "api4preview.sapsf.com",
    ("DC4", "sales_demo"): "api68sales.successfactors.com",
    ("DC68", "production"): "api4.successfactors.com",
    ("DC68", "preview"): "api4preview.sapsf.com",
    ("DC68", "sales_demo"): "api68sales.successfactors.com",

    # DC40 - Sales Demo (Azure)
    ("DC40", "sales_demo"): "api40sales.sapsf.com",

    # DC41 - Virginia, US (Azure)
    ("DC41", "production"): "api41.sapsf.com",
    ("DC41", "preview"): "api41preview.sapsf.com",

    # DC44 / DC52 - Singapore (GCP)
    ("DC44", "production"): "api44.sapsf.com",
    ("DC44", "preview"): "api44preview.sapsf.com",
    ("DC52", "production"): "api44.sapsf.com",
    ("DC52", "preview"): "api44preview.sapsf.com",

    # DC47 - Canada Central (Azure)
    ("DC47", "production"): "api47.sapsf.com",
    ("DC47", "preview"): "api47preview.sapsf.com",

    # DC50 - Tokyo, Japan (GCP)
    ("DC50", "production"): "api50.sapsf.com",
    ("DC50", "preview"): "api50preview.sapsf.com",

    # DC55 - Frankfurt, Germany (GCP)
    ("DC55", "production"): "api55.sapsf.eu",
    ("DC55", "preview"): "api55preview.sapsf.eu",

    # DC74 - Zurich, Switzerland (Azure)
    ("DC74", "production"): "api74.sapsf.eu",
    ("DC74", "preview"): "api74preview.sapsf.eu",

    # DC8 / DC70 - Ashburn, Virginia, US (Azure)
    ("DC8", "production"): "api8.successfactors.com",
    ("DC8", "preview"): "api8preview.sapsf.com",
    ("DC8", "sales_demo"): "apisalesdemo8.successfactors.com",
    ("DC70", "production"): "api8.successfactors.com",
    ("DC70", "preview"): "api8preview.sapsf.com",
    ("DC70", "sales_demo"): "apisalesdemo8.successfactors.com",

    # DC80 - Mumbai, India (GCP)
    ("DC80", "production"): "api-in10.hr.cloud.sap",
    ("DC80", "preview"): "api-in10-preview.hr.cloud.sap",

    # DC82 - Riyadh, Saudi Arabia (GCP)
    ("DC82", "production"): "api-sa20.hr.cloud.sap",
    ("DC82", "preview"): "api-sa20-preview.hr.cloud.sap",
}

# Extract valid data centers and environments from the map
VALID_DATA_CENTERS = set(dc for dc, _ in DC_API_HOST_MAP.keys())
VALID_ENVIRONMENTS = {"production", "preview", "sales_demo"}


def get_api_host(data_center: str, environment: str) -> str:
    """
    Map data center and environment to API host.

    Args:
        data_center: SAP data center code (e.g., "DC55", "DC10")
        environment: Environment type ("preview", "production", "sales_demo")

    Returns:
        API host string (without https:// prefix)

    Raises:
        ValueError: If invalid data_center or environment, or combination not available
    """
    dc_upper = data_center.upper()
    env_lower = environment.lower()

    if dc_upper not in VALID_DATA_CENTERS:
        valid_dcs = ", ".join(sorted(VALID_DATA_CENTERS, key=lambda x: (int(x[2:]) if x[2:].isdigit() else 999, x)))
        raise ValueError(f"Invalid data_center '{data_center}'. Valid options: {valid_dcs}")

    if env_lower not in VALID_ENVIRONMENTS:
        raise ValueError(f"Invalid environment '{environment}'. Valid options: production, preview, sales_demo")

    key = (dc_upper, env_lower)
    if key not in DC_API_HOST_MAP:
        available_envs = [env for (dc, env) in DC_API_HOST_MAP.keys() if dc == dc_upper]
        raise ValueError(f"Environment '{environment}' not available for {data_center}. Available: {', '.join(available_envs)}")

    return DC_API_HOST_MAP[key]
