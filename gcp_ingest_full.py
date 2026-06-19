"""
gcp_ingest_full.py — CloudPath GCP ingestor (FULL / INDUSTRIAL)

Complete GCP resource ingestion targeting Cartography-equivalent coverage.
Designed for industrial use: handles missing APIs gracefully, parameterized
for any GCP account, idempotent (safe to re-run).

Covers:
  Foundation       : Project, Instance, Bucket, ServiceAccount, Role, Firewall
  Compute Extended : Network, Subnet, Disk, Route, ForwardingRule
  IAM Deep         : CustomRole, ServiceAccountKey, deep project bindings
  Cloud SQL        : SQLInstance, SQLDatabase, SQLUser
  GKE              : Cluster, NodePool
  DNS              : ManagedZone, Record
  Serverless       : CloudFunction, CloudRunService
  Pub/Sub & BigQuery: PubSubTopic, PubSubSubscription, BigQueryDataset, BigQueryTable

Run with:
    $env:GOOGLE_APPLICATION_CREDENTIALS = "C:\\path\\to\\gcp-key.json"
    $env:GCP_PROJECT_ID = "your-project-id"
    $env:NEO4J_PASSWORD = "YourPassword123"
    python gcp_ingest_full.py

Optional flags:
    --skip-optional   Skip Cloud SQL, GKE, Serverless, Pub/Sub, BigQuery
                      (use if those APIs are not enabled in the project)
"""
import os
import sys
import argparse
from neo4j import GraphDatabase
from google.api_core import exceptions as gcp_exceptions

# Core imports (always needed)
from google.cloud import compute_v1, storage, iam_admin_v1, resourcemanager_v3
from google.iam.v1 import iam_policy_pb2


# ==============================================================
# CONFIGURATION
# ==============================================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "YourPassword123")
PROJECT_ID = os.environ.get("GCP_PROJECT_ID")

if not PROJECT_ID:
    print("ERROR: Set GCP_PROJECT_ID environment variable.")
    sys.exit(1)

KEY_FILE = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
if not KEY_FILE or not os.path.exists(KEY_FILE):
    print("ERROR: Set GOOGLE_APPLICATION_CREDENTIALS to your gcp-key.json path.")
    sys.exit(1)


# ==============================================================
# UTILITY HELPERS
# ==============================================================
def safe_call(label, fn, *args, **kwargs):
    """Run an ingestion function, catch API-disabled / permission errors
    gracefully so the rest of the sync can continue."""
    try:
        return fn(*args, **kwargs)
    except gcp_exceptions.PermissionDenied as e:
        print(f"  [{label}] SKIPPED (permission denied): {str(e)[:80]}")
        return 0
    except gcp_exceptions.NotFound as e:
        print(f"  [{label}] SKIPPED (not found / API may be disabled)")
        return 0
    except gcp_exceptions.FailedPrecondition as e:
        print(f"  [{label}] SKIPPED (API not enabled in project)")
        return 0
    except Exception as e:
        print(f"  [{label}] ERROR: {type(e).__name__}: {str(e)[:100]}")
        return 0


def merge_project(session, project_id):
    session.run(
        """
        MERGE (p:GCPProject {id: $pid})
        SET p.name = $pid, p.lastupdated = timestamp()
        """,
        pid=project_id,
    )


# ==============================================================
# SECTION 1 — FOUNDATION
# Compute instances, storage buckets, service accounts,
# project IAM, firewalls
# ==============================================================
def ingest_instances(session, project_id):
    client = compute_v1.InstancesClient()
    request = compute_v1.AggregatedListInstancesRequest(project=project_id)
    count = 0
    for zone_name, response in client.aggregated_list(request=request):
        if not response.instances:
            continue
        for instance in response.instances:
            sa_emails = [sa.email for sa in instance.service_accounts]
            network_tags = list(instance.tags.items) if instance.tags else []

            # External IPs from network interfaces
            ext_ips = []
            # Networks the instance is attached to (used by firewall match logic)
            attached_networks = []
            for ni in instance.network_interfaces:
                if ni.network:
                    attached_networks.append(ni.network.split("/")[-1])
                for ac in ni.access_configs:
                    if ac.nat_i_p:
                        ext_ips.append(ac.nat_i_p)

            session.run(
                """
                MERGE (i:GCPInstance {id: $id})
                SET i.name = $name,
                    i.status = $status,
                    i.zone = $zone,
                    i.machine_type = $mtype,
                    i.tags = $tags,
                    i.external_ips = $ext_ips,
                    i.has_public_ip = $has_pub,
                    i.networks = $networks,
                    i.service_account_emails = $sa_emails,
                    i.lastupdated = timestamp()
                WITH i
                MATCH (p:GCPProject {id: $pid})
                MERGE (p)-[:RESOURCE]->(i)
                """,
                id=str(instance.id),
                name=instance.name,
                status=instance.status,
                zone=instance.zone.split("/")[-1],
                mtype=instance.machine_type.split("/")[-1],
                tags=network_tags,
                ext_ips=ext_ips,
                has_pub=bool(ext_ips),
                networks=attached_networks,
                sa_emails=sa_emails,
                pid=project_id,
            )

            for sa_email in sa_emails:
                session.run(
                    """
                    MERGE (sa:GCPServiceAccount {email: $email})
                    WITH sa
                    MATCH (i:GCPInstance {id: $id})
                    MERGE (i)-[:USES_SERVICE_ACCOUNT]->(sa)
                    """,
                    email=sa_email,
                    id=str(instance.id),
                )
            count += 1
    print(f"  [Compute] Ingested {count} instance(s)")
    return count


def ingest_buckets(session, project_id):
    client = storage.Client(project=project_id)
    count = 0
    public_count = 0
    for bucket in client.list_buckets():
        session.run(
            """
            MERGE (b:GCPBucket {name: $name})
            SET b.location = $loc,
                b.storage_class = $sc,
                b.versioning_enabled = $ver,
                b.lastupdated = timestamp()
            WITH b
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(b)
            """,
            name=bucket.name,
            loc=bucket.location,
            sc=bucket.storage_class,
            ver=bool(bucket.versioning_enabled),
            pid=project_id,
        )

        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                role = binding.get("role", "")
                members = list(binding.get("members", []))
                is_public = "allUsers" in members or "allAuthenticatedUsers" in members

                session.run(
                    """
                    MATCH (b:GCPBucket {name: $name})
                    MERGE (p:GCPBucketIAMPolicy {bucket_name: $name, role: $role})
                    SET p.members = $members, p.is_public = $is_public
                    MERGE (b)-[:IAM_POLICY]->(p)
                    """,
                    name=bucket.name,
                    role=role,
                    members=members,
                    is_public=is_public,
                )
                if is_public:
                    public_count += 1
        except Exception as e:
            print(f"    (could not read IAM for {bucket.name}: {str(e)[:60]})")
        count += 1
    print(f"  [Storage] Ingested {count} bucket(s), {public_count} public binding(s)")
    return count


def ingest_service_accounts(session, project_id):
    client = iam_admin_v1.IAMClient()
    request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
    count = 0
    for sa in client.list_service_accounts(request=request).accounts:
        session.run(
            """
            MERGE (sa:GCPServiceAccount {email: $email})
            SET sa.display_name = $dn,
                sa.unique_id = $uid,
                sa.disabled = $dis,
                sa.lastupdated = timestamp()
            WITH sa
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(sa)
            """,
            email=sa.email,
            dn=sa.display_name,
            uid=sa.unique_id,
            dis=sa.disabled,
            pid=project_id,
        )
        count += 1
    print(f"  [IAM] Ingested {count} service account(s)")

    # Project-level IAM bindings
    pm_client = resourcemanager_v3.ProjectsClient()
    request = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{project_id}")
    policy = pm_client.get_iam_policy(request=request)

    binding_count = 0
    for binding in policy.bindings:
        role = binding.role
        for member in binding.members:
            if member.startswith("serviceAccount:"):
                email = member.split(":", 1)[1]
                session.run(
                    """
                    MERGE (sa:GCPServiceAccount {email: $email})
                    MERGE (r:GCPRole {name: $role})
                    MERGE (sa)-[b:HAS_ROLE {project_id: $pid}]->(r)
                    SET b.lastupdated = timestamp()
                    """,
                    email=email,
                    role=role,
                    pid=project_id,
                )
                binding_count += 1
            elif member.startswith("user:"):
                # Track human user bindings too
                email = member.split(":", 1)[1]
                session.run(
                    """
                    MERGE (u:GCPUser {email: $email})
                    MERGE (r:GCPRole {name: $role})
                    MERGE (u)-[b:HAS_ROLE {project_id: $pid}]->(r)
                    SET b.lastupdated = timestamp()
                    """,
                    email=email,
                    role=role,
                    pid=project_id,
                )
                binding_count += 1
    print(f"  [IAM] Linked {binding_count} role binding(s)")
    return count


def ingest_firewalls(session, project_id):
    """Capture firewalls including which instances they apply to.

    A GCP firewall rule applies to:
      - All instances in its network if no target_tags AND no target_service_accounts
      - Instances with matching network tags (if target_tags set)
      - Instances using matching service accounts (if target_service_accounts set)

    We store all three fields so detection rules can correctly determine
    whether a given instance is actually exposed by a given firewall.
    """
    client = compute_v1.FirewallsClient()
    request = compute_v1.ListFirewallsRequest(project=project_id)
    count = 0
    open_count = 0
    for fw in client.list(request=request):
        source_ranges = list(fw.source_ranges)
        is_open = "0.0.0.0/0" in source_ranges

        allowed = []
        for a in fw.allowed:
            for p in (a.ports or ["all"]):
                allowed.append(f"{a.I_p_protocol}:{p}")

        target_tags = list(fw.target_tags) if fw.target_tags else []
        target_sas = list(fw.target_service_accounts) if fw.target_service_accounts else []
        # "Applies to all" when neither tags nor SAs are set
        applies_to_all_in_network = (not target_tags) and (not target_sas)

        session.run(
            """
            MERGE (f:GCPFirewall {name: $name})
            SET f.network = $net,
                f.direction = $dir,
                f.source_ranges = $sr,
                f.allowed = $allowed,
                f.is_open_to_internet = $open,
                f.target_tags = $ttags,
                f.target_service_accounts = $tsas,
                f.applies_to_all_in_network = $all,
                f.priority = $priority,
                f.disabled = $disabled,
                f.lastupdated = timestamp()
            WITH f
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(f)
            """,
            name=fw.name,
            net=fw.network.split("/")[-1],
            dir=fw.direction,
            sr=source_ranges,
            allowed=allowed,
            open=is_open,
            ttags=target_tags,
            tsas=target_sas,
            all=applies_to_all_in_network,
            priority=fw.priority,
            disabled=bool(fw.disabled),
            pid=project_id,
        )
        if is_open:
            open_count += 1
        count += 1
    print(f"  [Firewall] Ingested {count} rule(s), {open_count} open to internet")
    return count


# ==============================================================
# SECTION 2 — COMPUTE EXTENDED
# VPC networks, subnets, disks, routes, forwarding rules
# ==============================================================
def ingest_networks(session, project_id):
    client = compute_v1.NetworksClient()
    request = compute_v1.ListNetworksRequest(project=project_id)
    count = 0
    for net in client.list(request=request):
        rmode = net.routing_config.routing_mode if net.routing_config else "REGIONAL"
        session.run(
            """
            MERGE (n:GCPNetwork {id: $id})
            SET n.name = $name,
                n.auto_create_subnetworks = $auto,
                n.routing_mode = $rmode,
                n.lastupdated = timestamp()
            WITH n
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(n)
            """,
            id=str(net.id),
            name=net.name,
            auto=bool(net.auto_create_subnetworks),
            rmode=rmode,
            pid=project_id,
        )
        count += 1
    print(f"  [Network] Ingested {count} VPC network(s)")
    return count


def ingest_subnets(session, project_id):
    client = compute_v1.SubnetworksClient()
    request = compute_v1.AggregatedListSubnetworksRequest(project=project_id)
    count = 0
    for region_name, response in client.aggregated_list(request=request):
        if not response.subnetworks:
            continue
        for sub in response.subnetworks:
            net_name = sub.network.split("/")[-1] if sub.network else ""
            session.run(
                """
                MERGE (s:GCPSubnet {id: $id})
                SET s.name = $name,
                    s.region = $region,
                    s.cidr_range = $cidr,
                    s.private_ip_google_access = $priv,
                    s.lastupdated = timestamp()
                WITH s
                MATCH (p:GCPProject {id: $pid})
                MERGE (p)-[:RESOURCE]->(s)
                WITH s
                MATCH (n:GCPNetwork {name: $netname})
                MERGE (s)-[:IN_NETWORK]->(n)
                """,
                id=str(sub.id),
                name=sub.name,
                region=sub.region.split("/")[-1],
                cidr=sub.ip_cidr_range,
                priv=bool(sub.private_ip_google_access),
                pid=project_id,
                netname=net_name,
            )
            count += 1
    print(f"  [Subnet] Ingested {count} subnet(s)")
    return count


def ingest_disks(session, project_id):
    client = compute_v1.DisksClient()
    request = compute_v1.AggregatedListDisksRequest(project=project_id)
    count = 0
    unencrypted = 0
    for zone_name, response in client.aggregated_list(request=request):
        if not response.disks:
            continue
        for disk in response.disks:
            cmek = bool(
                disk.disk_encryption_key and disk.disk_encryption_key.kms_key_name
            )
            if not cmek:
                unencrypted += 1
            session.run(
                """
                MERGE (d:GCPDisk {id: $id})
                SET d.name = $name,
                    d.zone = $zone,
                    d.size_gb = $size,
                    d.type = $type,
                    d.status = $status,
                    d.cmek_enabled = $cmek,
                    d.source_image = $src,
                    d.lastupdated = timestamp()
                WITH d
                MATCH (p:GCPProject {id: $pid})
                MERGE (p)-[:RESOURCE]->(d)
                """,
                id=str(disk.id),
                name=disk.name,
                zone=disk.zone.split("/")[-1] if disk.zone else "",
                size=disk.size_gb,
                type=disk.type_.split("/")[-1] if disk.type_ else "",
                status=disk.status,
                cmek=cmek,
                src=disk.source_image.split("/")[-1] if disk.source_image else "",
                pid=project_id,
            )

            for user_url in disk.users:
                inst_name = user_url.split("/")[-1]
                session.run(
                    """
                    MATCH (i:GCPInstance {name: $iname})
                    MATCH (d:GCPDisk {id: $did})
                    MERGE (i)-[:ATTACHED_DISK]->(d)
                    """,
                    iname=inst_name,
                    did=str(disk.id),
                )
            count += 1
    print(f"  [Disk] Ingested {count} disk(s), {unencrypted} without CMEK")
    return count


def ingest_routes(session, project_id):
    client = compute_v1.RoutesClient()
    request = compute_v1.ListRoutesRequest(project=project_id)
    count = 0
    internet_routes = 0
    for route in client.list(request=request):
        net_name = route.network.split("/")[-1] if route.network else ""
        next_hop_internet = bool(
            route.next_hop_gateway and "default-internet-gateway" in route.next_hop_gateway
        )
        if next_hop_internet:
            internet_routes += 1
        session.run(
            """
            MERGE (r:GCPRoute {id: $id})
            SET r.name = $name,
                r.dest_range = $dest,
                r.priority = $priority,
                r.tags = $tags,
                r.next_hop_internet = $hop_inet,
                r.next_hop_ip = $hop_ip,
                r.lastupdated = timestamp()
            WITH r
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(r)
            WITH r
            MATCH (n:GCPNetwork {name: $netname})
            MERGE (r)-[:IN_NETWORK]->(n)
            """,
            id=str(route.id),
            name=route.name,
            dest=route.dest_range,
            priority=route.priority,
            tags=list(route.tags) if route.tags else [],
            hop_inet=next_hop_internet,
            hop_ip=route.next_hop_ip or "",
            pid=project_id,
            netname=net_name,
        )
        count += 1
    print(f"  [Route] Ingested {count} route(s), {internet_routes} to internet gateway")
    return count


def ingest_forwarding_rules(session, project_id):
    client = compute_v1.ForwardingRulesClient()
    request = compute_v1.AggregatedListForwardingRulesRequest(project=project_id)
    count = 0
    public = 0
    for region_name, response in client.aggregated_list(request=request):
        if not response.forwarding_rules:
            continue
        for fr in response.forwarding_rules:
            is_external = fr.load_balancing_scheme in ("EXTERNAL", "EXTERNAL_MANAGED")
            if is_external:
                public += 1
            session.run(
                """
                MERGE (fr:GCPForwardingRule {id: $id})
                SET fr.name = $name,
                    fr.region = $region,
                    fr.ip_address = $ip,
                    fr.ip_protocol = $proto,
                    fr.port_range = $ports,
                    fr.load_balancing_scheme = $lbs,
                    fr.is_external = $ext,
                    fr.lastupdated = timestamp()
                WITH fr
                MATCH (p:GCPProject {id: $pid})
                MERGE (p)-[:RESOURCE]->(fr)
                """,
                id=str(fr.id),
                name=fr.name,
                region=fr.region.split("/")[-1] if fr.region else "global",
                ip=fr.I_p_address or "",
                proto=fr.I_p_protocol or "",
                ports=fr.port_range or "",
                lbs=fr.load_balancing_scheme,
                ext=is_external,
                pid=project_id,
            )
            count += 1
    print(f"  [ForwardingRule] Ingested {count} rule(s), {public} external")
    return count


# ==============================================================
# SECTION 3 — IAM DEEP
# Custom roles, service account keys
# ==============================================================
def ingest_custom_roles(session, project_id):
    client = iam_admin_v1.IAMClient()
    parent = f"projects/{project_id}"
    request = iam_admin_v1.ListRolesRequest(parent=parent, show_deleted=False)
    count = 0
    for role in client.list_roles(request=request).roles:
        permissions = list(role.included_permissions) if role.included_permissions else []
        session.run(
            """
            MERGE (r:GCPRole {name: $name})
            SET r.title = $title,
                r.description = $desc,
                r.stage = $stage,
                r.deleted = $deleted,
                r.is_custom = true,
                r.permissions = $perms,
                r.permission_count = $pcount,
                r.lastupdated = timestamp()
            WITH r
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(r)
            """,
            name=role.name,
            title=role.title,
            desc=role.description,
            stage=role.stage.name if hasattr(role.stage, "name") else str(role.stage),
            deleted=role.deleted,
            perms=permissions,
            pcount=len(permissions),
            pid=project_id,
        )
        count += 1
    print(f"  [CustomRole] Ingested {count} custom role(s)")
    return count


def ingest_service_account_keys(session, project_id):
    """Lists user-managed keys for every service account.
    System-managed keys are excluded (they rotate automatically)."""
    client = iam_admin_v1.IAMClient()
    sa_request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
    count = 0
    for sa in client.list_service_accounts(request=sa_request).accounts:
        try:
            key_request = iam_admin_v1.ListServiceAccountKeysRequest(
                name=sa.name,
                key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED],
            )
            keys = client.list_service_account_keys(request=key_request)
            for key in keys.keys:
                session.run(
                    """
                    MERGE (k:GCPServiceAccountKey {name: $name})
                    SET k.key_id = $kid,
                        k.created = $created,
                        k.expires = $expires,
                        k.algorithm = $algo,
                        k.lastupdated = timestamp()
                    WITH k
                    MATCH (sa:GCPServiceAccount {email: $email})
                    MERGE (sa)-[:HAS_KEY]->(k)
                    """,
                    name=key.name,
                    kid=key.name.split("/")[-1],
                    created=str(key.valid_after_time) if key.valid_after_time else "",
                    expires=str(key.valid_before_time) if key.valid_before_time else "",
                    algo=(
                        key.key_algorithm.name
                        if hasattr(key.key_algorithm, "name")
                        else str(key.key_algorithm)
                    ),
                    email=sa.email,
                )
                count += 1
        except Exception as e:
            print(f"    (could not list keys for {sa.email}: {str(e)[:60]})")
    print(f"  [SAKey] Ingested {count} user-managed key(s)")
    return count


# ==============================================================
# SECTION 4 — CLOUD SQL
# SQL instances, databases, users
# ==============================================================
def ingest_cloudsql(session, project_id):
    # Use the discovery-based API client because google-cloud-sql is split
    from googleapiclient import discovery

    service = discovery.build("sqladmin", "v1", cache_discovery=False)
    instances_count = 0
    db_count = 0
    user_count = 0

    inst_resp = service.instances().list(project=project_id).execute()
    for inst in inst_resp.get("items", []):
        name = inst.get("name", "")
        ip_addresses = inst.get("ipAddresses", [])
        has_public_ip = any(
            ip.get("type") == "PRIMARY" for ip in ip_addresses
        )
        ssl_required = inst.get("settings", {}).get("ipConfiguration", {}).get(
            "requireSsl", False
        )
        authorized_networks = inst.get("settings", {}).get("ipConfiguration", {}).get(
            "authorizedNetworks", []
        )
        is_open_to_internet = any(
            n.get("value") == "0.0.0.0/0" for n in authorized_networks
        )

        session.run(
            """
            MERGE (s:GCPSQLInstance {name: $name})
            SET s.database_version = $dbv,
                s.region = $region,
                s.state = $state,
                s.tier = $tier,
                s.has_public_ip = $pub,
                s.ssl_required = $ssl,
                s.is_open_to_internet = $open,
                s.lastupdated = timestamp()
            WITH s
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(s)
            """,
            name=name,
            dbv=inst.get("databaseVersion", ""),
            region=inst.get("region", ""),
            state=inst.get("state", ""),
            tier=inst.get("settings", {}).get("tier", ""),
            pub=has_public_ip,
            ssl=ssl_required,
            open=is_open_to_internet,
            pid=project_id,
        )
        instances_count += 1

        # Databases on this instance
        try:
            db_resp = service.databases().list(
                project=project_id, instance=name
            ).execute()
            for db in db_resp.get("items", []):
                session.run(
                    """
                    MERGE (d:GCPSQLDatabase {name: $name, instance: $iname})
                    SET d.charset = $charset, d.collation = $coll
                    WITH d
                    MATCH (s:GCPSQLInstance {name: $iname})
                    MERGE (s)-[:HAS_DATABASE]->(d)
                    """,
                    name=db.get("name", ""),
                    iname=name,
                    charset=db.get("charset", ""),
                    coll=db.get("collation", ""),
                )
                db_count += 1
        except Exception:
            pass

        # Users on this instance
        try:
            user_resp = service.users().list(
                project=project_id, instance=name
            ).execute()
            for u in user_resp.get("items", []):
                session.run(
                    """
                    MERGE (u:GCPSQLUser {name: $name, instance: $iname})
                    SET u.host = $host
                    WITH u
                    MATCH (s:GCPSQLInstance {name: $iname})
                    MERGE (s)-[:HAS_SQL_USER]->(u)
                    """,
                    name=u.get("name", ""),
                    iname=name,
                    host=u.get("host", ""),
                )
                user_count += 1
        except Exception:
            pass
    print(
        f"  [CloudSQL] Ingested {instances_count} instance(s), "
        f"{db_count} database(s), {user_count} user(s)"
    )
    return instances_count


# ==============================================================
# SECTION 5 — GKE
# Kubernetes clusters and node pools
# ==============================================================
def ingest_gke(session, project_id):
    from google.cloud import container_v1

    client = container_v1.ClusterManagerClient()
    parent = f"projects/{project_id}/locations/-"
    response = client.list_clusters(parent=parent)

    cluster_count = 0
    pool_count = 0
    for cluster in response.clusters:
        public_endpoint = bool(cluster.endpoint and not (
            cluster.private_cluster_config
            and cluster.private_cluster_config.enable_private_endpoint
        ))
        legacy_abac = bool(cluster.legacy_abac and cluster.legacy_abac.enabled)
        network_policy = bool(
            cluster.network_policy and cluster.network_policy.enabled
        )

        session.run(
            """
            MERGE (c:GCPGKECluster {name: $name})
            SET c.location = $loc,
                c.endpoint = $endpoint,
                c.status = $status,
                c.current_master_version = $ver,
                c.network = $network,
                c.subnetwork = $subnet,
                c.has_public_endpoint = $pub,
                c.legacy_abac_enabled = $abac,
                c.network_policy_enabled = $netpol,
                c.lastupdated = timestamp()
            WITH c
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(c)
            """,
            name=cluster.name,
            loc=cluster.location,
            endpoint=cluster.endpoint or "",
            status=cluster.status.name if hasattr(cluster.status, "name") else str(cluster.status),
            ver=cluster.current_master_version,
            network=cluster.network or "",
            subnet=cluster.subnetwork or "",
            pub=public_endpoint,
            abac=legacy_abac,
            netpol=network_policy,
            pid=project_id,
        )
        cluster_count += 1

        for pool in cluster.node_pools:
            sa_email = (
                pool.config.service_account if pool.config and pool.config.service_account else ""
            )
            session.run(
                """
                MERGE (np:GCPGKENodePool {name: $name, cluster: $cluster})
                SET np.machine_type = $mt,
                    np.initial_node_count = $nc,
                    np.auto_upgrade = $upg,
                    np.auto_repair = $rep,
                    np.service_account = $sa,
                    np.lastupdated = timestamp()
                WITH np
                MATCH (c:GCPGKECluster {name: $cluster})
                MERGE (c)-[:HAS_NODEPOOL]->(np)
                """,
                name=pool.name,
                cluster=cluster.name,
                mt=pool.config.machine_type if pool.config else "",
                nc=pool.initial_node_count,
                upg=bool(pool.management.auto_upgrade) if pool.management else False,
                rep=bool(pool.management.auto_repair) if pool.management else False,
                sa=sa_email,
            )

            # Link node pool to its service account (privilege escalation paths)
            if sa_email and sa_email != "default":
                session.run(
                    """
                    MERGE (sa:GCPServiceAccount {email: $email})
                    WITH sa
                    MATCH (np:GCPGKENodePool {name: $name, cluster: $cluster})
                    MERGE (np)-[:USES_SERVICE_ACCOUNT]->(sa)
                    """,
                    email=sa_email,
                    name=pool.name,
                    cluster=cluster.name,
                )
            pool_count += 1
    print(f"  [GKE] Ingested {cluster_count} cluster(s), {pool_count} node pool(s)")
    return cluster_count


# ==============================================================
# SECTION 6 — DNS
# Managed zones and records
# ==============================================================
def ingest_dns(session, project_id):
    from google.cloud import dns

    client = dns.Client(project=project_id)
    zone_count = 0
    record_count = 0

    for zone in client.list_zones():
        session.run(
            """
            MERGE (z:GCPDNSZone {name: $name})
            SET z.dns_name = $dns,
                z.visibility = $vis,
                z.description = $desc,
                z.lastupdated = timestamp()
            WITH z
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(z)
            """,
            name=zone.name,
            dns=zone.dns_name,
            vis=zone.visibility or "public",
            desc=zone.description or "",
            pid=project_id,
        )
        zone_count += 1

        try:
            for record in zone.list_resource_record_sets():
                # Records relevant for subdomain takeover detection
                session.run(
                    """
                    MERGE (r:GCPDNSRecord {zone: $zone, name: $name, type: $type})
                    SET r.ttl = $ttl,
                        r.rrdatas = $data,
                        r.lastupdated = timestamp()
                    WITH r
                    MATCH (z:GCPDNSZone {name: $zone})
                    MERGE (z)-[:HAS_RECORD]->(r)
                    """,
                    zone=zone.name,
                    name=record.name,
                    type=record.record_type,
                    ttl=record.ttl,
                    data=list(record.rrdatas) if record.rrdatas else [],
                )
                record_count += 1
        except Exception as e:
            print(f"    (could not list records for {zone.name}: {str(e)[:60]})")
    print(f"  [DNS] Ingested {zone_count} zone(s), {record_count} record(s)")
    return zone_count


# ==============================================================
# SECTION 7 — SERVERLESS
# Cloud Functions and Cloud Run services
# ==============================================================
def ingest_cloud_functions(session, project_id):
    from google.cloud import functions_v2

    client = functions_v2.FunctionServiceClient()
    parent = f"projects/{project_id}/locations/-"
    count = 0
    for func in client.list_functions(parent=parent):
        sa_email = ""
        ingress = ""
        if func.service_config:
            sa_email = func.service_config.service_account_email or ""
            ingress = (
                func.service_config.ingress_settings.name
                if func.service_config.ingress_settings
                else ""
            )

        session.run(
            """
            MERGE (f:GCPCloudFunction {name: $name})
            SET f.state = $state,
                f.environment = $env,
                f.ingress_settings = $ingress,
                f.service_account = $sa,
                f.lastupdated = timestamp()
            WITH f
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(f)
            """,
            name=func.name,
            state=func.state.name if hasattr(func.state, "name") else str(func.state),
            env=func.environment.name if hasattr(func.environment, "name") else str(func.environment),
            ingress=ingress,
            sa=sa_email,
            pid=project_id,
        )

        if sa_email:
            session.run(
                """
                MERGE (sa:GCPServiceAccount {email: $email})
                WITH sa
                MATCH (f:GCPCloudFunction {name: $name})
                MERGE (f)-[:USES_SERVICE_ACCOUNT]->(sa)
                """,
                email=sa_email,
                name=func.name,
            )
        count += 1
    print(f"  [CloudFunction] Ingested {count} function(s)")
    return count


def ingest_cloud_run(session, project_id):
    from google.cloud import run_v2

    client = run_v2.ServicesClient()
    parent = f"projects/{project_id}/locations/-"
    count = 0
    public_count = 0
    for svc in client.list_services(parent=parent):
        # Check ingress and IAM policy
        ingress = svc.ingress.name if hasattr(svc.ingress, "name") else str(svc.ingress)
        # Public ingress without auth = potentially world-accessible
        is_public = ingress == "INGRESS_TRAFFIC_ALL"
        sa_email = svc.template.service_account if svc.template else ""

        session.run(
            """
            MERGE (s:GCPCloudRunService {name: $name})
            SET s.uri = $uri,
                s.ingress = $ingress,
                s.is_public_ingress = $pub,
                s.service_account = $sa,
                s.lastupdated = timestamp()
            WITH s
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(s)
            """,
            name=svc.name,
            uri=svc.uri or "",
            ingress=ingress,
            pub=is_public,
            sa=sa_email,
            pid=project_id,
        )

        if sa_email:
            session.run(
                """
                MERGE (sa:GCPServiceAccount {email: $email})
                WITH sa
                MATCH (s:GCPCloudRunService {name: $name})
                MERGE (s)-[:USES_SERVICE_ACCOUNT]->(sa)
                """,
                email=sa_email,
                name=svc.name,
            )
        if is_public:
            public_count += 1
        count += 1
    print(f"  [CloudRun] Ingested {count} service(s), {public_count} with public ingress")
    return count


# ==============================================================
# SECTION 8 — PUB/SUB & BIGQUERY
# Messaging and analytics resources
# ==============================================================
def ingest_pubsub(session, project_id):
    from google.cloud import pubsub_v1

    pub_client = pubsub_v1.PublisherClient()
    sub_client = pubsub_v1.SubscriberClient()

    topic_count = 0
    project_path = f"projects/{project_id}"
    for topic in pub_client.list_topics(request={"project": project_path}):
        session.run(
            """
            MERGE (t:GCPPubSubTopic {name: $name})
            SET t.kms_key = $kms, t.lastupdated = timestamp()
            WITH t
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(t)
            """,
            name=topic.name,
            kms=topic.kms_key_name or "",
            pid=project_id,
        )
        topic_count += 1

    sub_count = 0
    for sub in sub_client.list_subscriptions(request={"project": project_path}):
        session.run(
            """
            MERGE (s:GCPPubSubSubscription {name: $name})
            SET s.topic = $topic,
                s.ack_deadline = $ack,
                s.retain_acked_messages = $retain,
                s.lastupdated = timestamp()
            WITH s
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(s)
            WITH s
            MATCH (t:GCPPubSubTopic {name: $topic})
            MERGE (s)-[:SUBSCRIBES_TO]->(t)
            """,
            name=sub.name,
            topic=sub.topic,
            ack=sub.ack_deadline_seconds,
            retain=bool(sub.retain_acked_messages),
            pid=project_id,
        )
        sub_count += 1
    print(f"  [PubSub] Ingested {topic_count} topic(s), {sub_count} subscription(s)")
    return topic_count


def ingest_bigquery(session, project_id):
    from google.cloud import bigquery

    client = bigquery.Client(project=project_id)
    dataset_count = 0
    table_count = 0

    for dataset_ref in client.list_datasets():
        ds = client.get_dataset(dataset_ref.reference)
        # Check for public access
        public = False
        for entry in (ds.access_entries or []):
            if entry.entity_id in ("allUsers", "allAuthenticatedUsers"):
                public = True
                break

        session.run(
            """
            MERGE (d:GCPBigQueryDataset {dataset_id: $did})
            SET d.location = $loc,
                d.description = $desc,
                d.is_public = $pub,
                d.default_table_expiration_ms = $exp,
                d.lastupdated = timestamp()
            WITH d
            MATCH (p:GCPProject {id: $pid})
            MERGE (p)-[:RESOURCE]->(d)
            """,
            did=ds.dataset_id,
            loc=ds.location,
            desc=ds.description or "",
            pub=public,
            exp=ds.default_table_expiration_ms or 0,
            pid=project_id,
        )
        dataset_count += 1

        for table_ref in client.list_tables(ds.reference):
            session.run(
                """
                MERGE (t:GCPBigQueryTable {table_id: $tid, dataset_id: $did})
                SET t.full_table_id = $full,
                    t.lastupdated = timestamp()
                WITH t
                MATCH (d:GCPBigQueryDataset {dataset_id: $did})
                MERGE (d)-[:HAS_TABLE]->(t)
                """,
                tid=table_ref.table_id,
                did=ds.dataset_id,
                full=f"{project_id}.{ds.dataset_id}.{table_ref.table_id}",
            )
            table_count += 1
    print(f"  [BigQuery] Ingested {dataset_count} dataset(s), {table_count} table(s)")
    return dataset_count


# ==============================================================
# MAIN
# ==============================================================
def main():
    parser = argparse.ArgumentParser(description="CloudPath GCP Full Ingestor")
    parser.add_argument(
        "--skip-optional",
        action="store_true",
        help="Skip Cloud SQL, GKE, DNS, Serverless, Pub/Sub, BigQuery "
             "(use if those APIs aren't enabled)",
    )
    args = parser.parse_args()

    print(f"[GCP Ingest FULL] Project: {PROJECT_ID}")
    print(f"[GCP Ingest FULL] Key file: {KEY_FILE}")
    print(f"[GCP Ingest FULL] Skip optional: {args.skip_optional}\n")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            merge_project(session, PROJECT_ID)

            # --- Section 1: Foundation ---
            print("=" * 60)
            print("SECTION 1: Foundation (Compute, Storage, IAM, Firewall)")
            print("=" * 60)
            safe_call("Instances", ingest_instances, session, PROJECT_ID)
            safe_call("Buckets", ingest_buckets, session, PROJECT_ID)
            safe_call("Service Accounts", ingest_service_accounts, session, PROJECT_ID)
            safe_call("Firewalls", ingest_firewalls, session, PROJECT_ID)

            # --- Section 2: Compute Extended ---
            print("\n" + "=" * 60)
            print("SECTION 2: Compute Extended (Networks, Subnets, Disks, Routes, LB)")
            print("=" * 60)
            safe_call("Networks", ingest_networks, session, PROJECT_ID)
            safe_call("Subnets", ingest_subnets, session, PROJECT_ID)
            safe_call("Disks", ingest_disks, session, PROJECT_ID)
            safe_call("Routes", ingest_routes, session, PROJECT_ID)
            safe_call("Forwarding Rules", ingest_forwarding_rules, session, PROJECT_ID)

            # --- Section 3: IAM Deep ---
            print("\n" + "=" * 60)
            print("SECTION 3: IAM Deep (Custom Roles, SA Keys)")
            print("=" * 60)
            safe_call("Custom Roles", ingest_custom_roles, session, PROJECT_ID)
            safe_call("Service Account Keys", ingest_service_account_keys, session, PROJECT_ID)

            if args.skip_optional:
                print("\n[Optional sections skipped via --skip-optional]")
            else:
                # --- Section 4: Cloud SQL ---
                print("\n" + "=" * 60)
                print("SECTION 4: Cloud SQL")
                print("=" * 60)
                safe_call("Cloud SQL", ingest_cloudsql, session, PROJECT_ID)

                # --- Section 5: GKE ---
                print("\n" + "=" * 60)
                print("SECTION 5: GKE (Kubernetes)")
                print("=" * 60)
                safe_call("GKE", ingest_gke, session, PROJECT_ID)

                # --- Section 6: DNS ---
                print("\n" + "=" * 60)
                print("SECTION 6: DNS")
                print("=" * 60)
                safe_call("DNS", ingest_dns, session, PROJECT_ID)

                # --- Section 7: Serverless ---
                print("\n" + "=" * 60)
                print("SECTION 7: Serverless (Cloud Functions, Cloud Run)")
                print("=" * 60)
                safe_call("Cloud Functions", ingest_cloud_functions, session, PROJECT_ID)
                safe_call("Cloud Run", ingest_cloud_run, session, PROJECT_ID)

                # --- Section 8: Pub/Sub & BigQuery ---
                print("\n" + "=" * 60)
                print("SECTION 8: Pub/Sub & BigQuery")
                print("=" * 60)
                safe_call("Pub/Sub", ingest_pubsub, session, PROJECT_ID)
                safe_call("BigQuery", ingest_bigquery, session, PROJECT_ID)

        print("\n" + "=" * 60)
        print("[GCP Ingest FULL] Complete.")
        print("=" * 60)
        print("Verify in Neo4j:")
        print(
            "    MATCH (n) WHERE labels(n)[0] STARTS WITH 'GCP' "
            "RETURN labels(n)[0] AS label, count(*) AS count ORDER BY count DESC"
        )
    finally:
        driver.close()


if __name__ == "__main__":
    main()