#!/usr/bin/env python3
"""
Campaign Technique Viewer - Executes campaign techniques via Caldera
Usage: python lib/run_campaign.py <campaign_name>
Example: python lib/run_campaign.py shadowray

UPDATED: Each node now has:
- environment_setup_commands: List of commands to prepare target with vulnerability/config
- attacker_commands: List of commands to execute from Kali to exploit
"""

import sys
from pathlib import Path
import yaml
import re
import uuid
import json
import subprocess
import time
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict, deque
from datetime import datetime

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    import config
except ImportError:
    print("❌ Could not import 'config' module.")
    sys.exit(1)

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("⚠️  Anthropic library not installed. Install with: pip install anthropic")

try:
    from openai import AzureOpenAI
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    print("⚠️  Azure OpenAI library not installed. Install with: pip install openai")

class CampaignRAGGenerator:
    def __init__(self):
        self.campaigns_dir = Path(config.CALDERA_ADVERSARIES_DIR)
        self.preprompt_file = project_root / "config" / "pre_prompt"
        self.preprompt_content = self.load_preprompt()
        self.operation_name = None
        self.operation_number = 1
        
        # MITRE ATT&CK technique dependencies
        self.technique_dependencies = {
            "discovery": ["initial-access", "execution"],
            "lateral-movement": ["discovery", "credential-access"],
            "collection": ["discovery", "lateral-movement"],
            "exfiltration": ["collection"],
            "credential-access": ["execution", "discovery"],
            "privilege-escalation": ["execution"],
            "persistence": ["execution"],
            "defense-evasion": [],
            "command-and-control": ["initial-access"],
            "impact": ["lateral-movement", "collection", "privilege-escalation"]
        }
        
        # What each tactic provides
        self.tactic_provides = {
            "initial-access": ["initial_access", "foothold"],
            "execution": ["code_execution"],
            "persistence": ["persistent_access"],
            "privilege-escalation": ["privileged_access", "higher_privileges"],
            "defense-evasion": ["evasion_capability"],
            "credential-access": ["credentials", "password_hashes", "secrets"],
            "discovery": ["system_info", "network_info", "user_info"],
            "lateral-movement": ["lateral_capability", "remote_access"],
            "collection": ["collected_data"],
            "command-and-control": ["c2_channel"],
            "exfiltration": ["exfiltrated_data"],
            "impact": ["disruption"],
            "reconnaissance": ["target_intel"],
            "resource-development": ["resources", "infrastructure"]
        }
        
        # What each technique ID specifically provides
        self.technique_specific_provides = {
            "T1078": ["valid_accounts"],
            "T1098": ["account_manipulation"],
            "T1136": ["new_account"],
            "T1003": ["password_hashes", "credentials"],
            "T1555": ["credentials_from_stores"],
            "T1087": ["account_discovery"],
            "T1482": ["domain_trust_discovery"],
            "T1018": ["remote_system_discovery"],
            "T1049": ["network_connections"],
            "T1057": ["process_discovery"],
            "T1082": ["system_info_discovery"],
            "T1016": ["network_config_discovery"],
            "T1033": ["user_discovery"],
            "T1071": ["c2_communication"],
            "T1572": ["protocol_tunneling"],
            "T1090": ["proxy_use"],
            "T1573": ["encrypted_channel"],
            "T1041": ["exfiltration_over_c2"],
            "T1048": ["exfiltration_over_alt_protocol"],
            "T1029": ["scheduled_exfiltration"]
        }

    def load_preprompt(self) -> str:
        """Load the pre-prompt content from file"""
        try:
            if self.preprompt_file.exists():
                with open(self.preprompt_file, 'r', encoding='utf-8') as f:
                    return f.read().strip()
            else:
                print(f"⚠️  Pre-prompt file not found: {self.preprompt_file}")
                return ""
        except Exception as e:
            print(f"⚠️  Error loading pre-prompt: {e}")
            return ""

    def find_campaign_file(self, campaign_name: str) -> Path:
        """Find campaign file by name (with or without 0. prefix)"""
        patterns = [
            f"0.{campaign_name}.yml",
            f"{campaign_name}.yml",
            f"0.{campaign_name}.yaml",
            f"{campaign_name}.yaml"
        ]

        if campaign_name.startswith("0."):
            patterns.insert(0, campaign_name)
            campaign_name = campaign_name[2:]

        for pattern in patterns:
            filepath = self.campaigns_dir / pattern
            if filepath.exists():
                return filepath

        matches = list(self.campaigns_dir.glob(f"*{campaign_name}*.yml"))
        if matches:
            return matches[0]

        raise FileNotFoundError(f"Campaign '{campaign_name}' not found in {self.campaigns_dir}")

    def load_campaign(self, filepath: Path) -> Dict[str, Any]:
        """Load and parse campaign YAML file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def remove_hyperlinks(self, text: str) -> str:
        """Remove hyperlinks from text while preserving the link text"""
        if not text:
            return text

        text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
        text = re.sub(r'https?://\S+', '', text)
        text = re.sub(r'\(Citation:.*?\)', '', text)
        text = re.sub(r'<[^>]+>', '', text)

        return text

    def extract_campaign_context(self, description: str) -> str:
        """Extract campaign context from description"""
        if not description:
            return ""

        context_marker = "**Campaign Context:**"
        if context_marker in description:
            after_marker = description.split(context_marker)[1]

            for end_marker in ["\n\n**", "\n\n", "**Additional", "**Citation", "**References"]:
                if end_marker in after_marker:
                    context = after_marker.split(end_marker)[0]
                    context = context.strip()
                    context = re.sub(r'\*\*', '', context)
                    context = re.sub(r'\n', ' ', context)
                    context = re.sub(r'\s+', ' ', context)
                    context = self.remove_hyperlinks(context)
                    return context

            context = after_marker.strip()
            context = re.sub(r'\*\*', '', context)
            context = re.sub(r'\n', ' ', context)
            context = re.sub(r'\s+', ' ', context)
            context = self.remove_hyperlinks(context)
            return context

        return ""

    def clean_description(self, description: str) -> str:
        """Clean description by removing campaign context and markdown"""
        if not description:
            return ""

        if "**Campaign Context:**" in description:
            description = description.split("**Campaign Context:**")[0].strip()

        additional_markers = ["**Additional References:**", "**References:**", "**Citation:**"]
        for marker in additional_markers:
            if marker in description:
                description = description.split(marker)[0].strip()

        description = re.sub(r'\*\*', '', description)
        description = re.sub(r'\(Citation:.*?\)', '', description)
        description = self.remove_hyperlinks(description)

        description = re.sub(r'\n+', '\n', description)
        description = re.sub(r' +', ' ', description)

        return description.strip()

    def extract_technique_info(self, technique_data: Dict[str, Any], technique_id: str) -> Dict[str, Any]:
        """Extract technique information from the campaign YAML structure"""
        description = technique_data.get('description', '')
        
        return {
            'id': technique_id,
            'technique_id': technique_data.get('technique_id', 'Unknown'),
            'technique_name': technique_data.get('technique_name', technique_data.get('name', 'Unknown')),
            'tactic': technique_data.get('tactic', 'Unknown'),
            'description': self.clean_description(description),
            'campaign_context': self.extract_campaign_context(description),
            'executors': technique_data.get('executors', [])
        }

    def determine_provides(self, technique: Dict[str, Any]) -> List[str]:
        """Determine what capabilities this technique provides"""
        provides = []
        tech_id = technique['technique_id']
        tactic = technique['tactic'].lower()
        
        # Add technique-specific provides
        if tech_id in self.technique_specific_provides:
            provides.extend(self.technique_specific_provides[tech_id])
        
        # Add tactic-based provides
        for tact_key, tact_provides in self.tactic_provides.items():
            if tact_key in tactic or tactic in tact_key:
                provides.extend(tact_provides)
        
        # Add generic provides based on technique
        if "discovery" in tactic:
            provides.append("discovered_info")
        if "credential" in tactic:
            provides.append("credentials")
        if "lateral" in tactic:
            provides.append("lateral_capability")
        if "privilege" in tactic:
            provides.append("privileged_access")
        if "persistence" in tactic:
            provides.append("persistent_access")
        if "execution" in tactic:
            provides.append("execution_capability")
        
        # Remove duplicates
        return list(set(provides))

    def determine_prerequisites(self, technique: Dict[str, Any], available_capabilities: Set[str] = None) -> List[str]:
        """Determine required prerequisites based on technique and available capabilities"""
        prerequisites = []
        tech_id = technique['technique_id']
        tactic = technique['tactic'].lower()
        
        if "execution" in tactic:
            prerequisites.append("access:initial")
            if not self._capability_available(available_capabilities, "execution_capability"):
                prerequisites.append("need:execution_vector")
        
        if "persistence" in tactic:
            prerequisites.append("access:initial")
            prerequisites.append("capability:write_to_persistence_locations")
        
        if "privilege-escalation" in tactic:
            prerequisites.append("access:low_privilege")
            if not self._capability_available(available_capabilities, "privileged_access"):
                prerequisites.append("need:privilege_escalation_vector")
        
        if "defense-evasion" in tactic:
            prerequisites.append("capability:modify_system_settings")
        
        if "credential-access" in tactic:
            prerequisites.append("access:target")
            if not self._capability_available(available_capabilities, "credentials"):
                prerequisites.append("need:credential_material_location")
        
        if "discovery" in tactic:
            prerequisites.append("access:target")
        
        if "lateral-movement" in tactic:
            prerequisites.append("access:host_a")
            prerequisites.append("credentials:target_host")
            if not self._capability_available(available_capabilities, "credentials"):
                prerequisites.append("need:valid_credentials")
        
        if "collection" in tactic:
            prerequisites.append("access:target")
            prerequisites.append("data:available")
        
        if "command-and-control" in tactic:
            prerequisites.append("access:initial")
            prerequisites.append("network:egress_allowed")
        
        if "exfiltration" in tactic:
            prerequisites.append("data:collected")
            prerequisites.append("c2:established")
            if not self._capability_available(available_capabilities, "c2_channel"):
                prerequisites.append("need:c2_channel")
        
        # Technique-specific prerequisites
        if tech_id == "T1003":  # Credential Dumping
            prerequisites.append("access:high_integrity")
            if not self._capability_available(available_capabilities, "privileged_access"):
                prerequisites.append("need:admin_or_system_access")
        
        if tech_id == "T1555":  # Credentials from Password Stores
            prerequisites.append("access:user_context")
        
        if tech_id == "T1087":  # Account Discovery
            prerequisites.append("access:target")
        
        if tech_id == "T1018":  # Remote System Discovery
            prerequisites.append("access:network")
            prerequisites.append("capability:network_scanning")
        
        return list(set(prerequisites))

    def _capability_available(self, available_capabilities: Set[str], needed: str) -> bool:
        """Check if a capability is available"""
        if available_capabilities is None:
            return False
        return needed in available_capabilities

    def generate_structural_node(self, technique: Dict[str, Any], index: int, available_capabilities: Set[str] = None) -> Dict[str, Any]:
        """Generate a structural node for the RAG"""
        node_id = str(uuid.uuid4())
        
        # Extract source and target host types from executors if available
        source_host_type = "kali"  # Default attacker host
        target_host_type = "debian-13"  # Default target host
        
        if technique.get('executors'):
            for executor in technique['executors']:
                if isinstance(executor, dict):
                    for exec_type, exec_data in executor.items():
                        if isinstance(exec_data, dict):
                            platform = exec_data.get('platform', '')
                            if 'windows' in platform.lower():
                                target_host_type = "windows-server"
                            elif 'linux' in platform.lower():
                                target_host_type = "debian-13"
                            elif 'darwin' in platform.lower():
                                target_host_type = "macos"
        
        # Determine what this node provides
        provides = self.determine_provides(technique)
        
        # Determine prerequisites considering available capabilities
        prerequisites = self.determine_prerequisites(technique, available_capabilities)
        
        # Generate AI prompt template
        ai_prompt = self.generate_ai_prompt(technique)
        
        structural_node = {
            "node_id": node_id,
            "node_index": index,
            "node_type": "structural",
            "technique_id": technique['technique_id'],
            "technique_name": technique['technique_name'],
            "tactic": technique['tactic'],
            "description": technique['description'],
            "campaign_context": technique['campaign_context'],
            "required_prerequisites": prerequisites,
            "provides": provides,
            
            # UPDATED: Separate environment setup and attacker commands
            "environment_setup_commands": [],  # Will be filled by LLM - runs on target
            "attacker_commands": [],  # Will be filled by LLM - runs from Kali
            
            "source_host_type": source_host_type,
            "target_host_type": target_host_type,
            "network_context": self.determine_network_context(technique),
            "parent_nodes": [],  # To be filled during DAG construction
            "child_nodes": [],  # To be filled during DAG construction
            "ai_prompt_template": ai_prompt,
            "validation_rules": self.get_validation_rules(technique),
            "cleanup_template": self.get_cleanup_template(technique),
            "satisfied_prerequisites": [],  # Will track which prerequisites are satisfied
            "unsatisfied_prerequisites": [],  # Will track which prerequisites are unsatisfied
            "executed": False,  # Track if node has been executed
            "execution_result": None,  # Store execution result
            "executor": None,  # Will be set based on command
            "discovered_ips": [],  # IPs discovered during execution
            "discovered_hostnames": [],  # Hostnames discovered during execution
            "discovered_usernames": []  # Usernames discovered during execution
        }
        
        return structural_node

    def generate_ai_prompt(self, technique: Dict[str, Any]) -> str:
        """Generate AI prompt template for the technique - UPDATED to request both command types"""
        prompt_parts = []
        
        if self.preprompt_content:
            prompt_parts.append(self.preprompt_content)
            prompt_parts.append("\n" + "="*80 + "\n")
        
        prompt_parts.append(f"TECHNIQUE: {technique['technique_id']} - {technique['technique_name']}")
        prompt_parts.append(f"TACTIC: {technique['tactic']}")
        
        if technique['campaign_context']:
            prompt_parts.append(f"CAMPAIGN CONTEXT: {technique['campaign_context']}")
        
        prompt_parts.append(f"\nTECHNIQUE DESCRIPTION:\n{technique['description']}")
        
        prompt_parts.append("""
For this MITRE ATT&CK technique, generate TWO sets of commands:

1) ENVIRONMENT_SETUP_COMMANDS:
   Commands to run on the TARGET system to create the vulnerability/misconfiguration
   that enables this technique. These prepare the environment for the attack.
   
   Output each command as:
   SETUP_CMD: <command to run on target>
   SETUP_DESC: <brief description>

2) ATTACKER_COMMANDS:
   Shell command(s) executed from Kali Linux that exploit the prepared environment
   and reproduce the behavioral characteristics of the technique.
   
   Output each command as:
   ATTACK_CMD: <command to run from Kali>
   ATTACK_DESC: <brief description>

Output strictly in this format:

ENVIRONMENT_SETUP_COMMANDS:
SETUP_CMD: <command 1>
SETUP_DESC: <description 1>
SETUP_CMD: <command 2>
SETUP_DESC: <description 2>

ATTACKER_COMMANDS:
ATTACK_CMD: <command 1>
ATTACK_DESC: <description 1>
ATTACK_CMD: <command 2>
ATTACK_DESC: <description 2>""")
        
        return "\n".join(prompt_parts)

    def determine_network_context(self, technique: Dict[str, Any]) -> str:
        """Determine network context requirements"""
        tactic = technique['tactic'].lower()
        
        if "initial-access" in tactic:
            return "Attacker can directly access Host A (from pre-prompt)"
        elif "lateral-movement" in tactic:
            return "Host A can access Host B (from pre-prompt)"
        elif "command-and-control" in tactic:
            return "Host A can initiate outbound connections (from pre-prompt)"
        elif "exfiltration" in tactic:
            return "Host A can establish outbound data transfer (from pre-prompt)"
        else:
            return "Network connectivity as defined in pre-prompt"

    def get_validation_rules(self, technique: Dict[str, Any]) -> List[str]:
        """Get validation rules for the technique"""
        rules = [
            "Command must execute without errors",
            "Expected artifacts must be generated",
            "Telemetry must be captured",
            "No unintended system modifications"
        ]
        
        tactic = technique['tactic'].lower()
        if "defense-evasion" in tactic:
            rules.append("Must evade default detection mechanisms")
        if "credential-access" in tactic:
            rules.append("Must not corrupt credential stores")
        
        return rules

    def get_cleanup_template(self, technique: Dict[str, Any]) -> str:
        """Get cleanup template for the technique"""
        tactic = technique['tactic'].lower()
        
        if "persistence" in tactic:
            return "Remove added persistence mechanism"
        elif "impact" in tactic:
            return "Restore affected files/services"
        elif "defense-evasion" in tactic:
            return "Restore original configurations"
        else:
            return "No cleanup required"

    def build_dag_relationships(self, structural_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build DAG relationships between structural nodes with prerequisite tracking"""
        nodes = structural_nodes.copy()
        
        # Track cumulative capabilities as we go through the DAG
        cumulative_capabilities = set()
        
        # First pass: establish parent-child relationships based on prerequisite satisfaction
        for i, node in enumerate(nodes):
            # Check which prerequisites can be satisfied by cumulative capabilities
            satisfied = []
            unsatisfied = []
            
            for prereq in node['required_prerequisites']:
                # Check if this prerequisite is satisfied by any previous node's provides
                prereq_satisfied = False
                for j in range(i):
                    prev_node = nodes[j]
                    if prereq in prev_node['provides'] or any(prereq in p for p in prev_node['provides']):
                        prereq_satisfied = True
                        # Add edge from provider to this node
                        if prev_node['node_id'] not in node['parent_nodes']:
                            node['parent_nodes'].append(prev_node['node_id'])
                        if node['node_id'] not in prev_node['child_nodes']:
                            prev_node['child_nodes'].append(node['node_id'])
                        break
                
                if prereq_satisfied:
                    satisfied.append(prereq)
                else:
                    unsatisfied.append(prereq)
            
            node['satisfied_prerequisites'] = satisfied
            node['unsatisfied_prerequisites'] = unsatisfied
            
            # Add this node's provides to cumulative capabilities
            cumulative_capabilities.update(node['provides'])
        
        # Second pass: add tactic-based dependencies
        for i, node in enumerate(nodes):
            node_tactic = node['tactic'].lower()
            
            # Find dependencies for this node's tactic
            for dep_tactic, depends_on in self.technique_dependencies.items():
                if dep_tactic in node_tactic or node_tactic in dep_tactic:
                    # Look for nodes that satisfy dependencies
                    for j, potential_parent in enumerate(nodes[:i]):
                        parent_tactic = potential_parent['tactic'].lower()
                        for required_dep in depends_on:
                            if required_dep in parent_tactic or parent_tactic in required_dep:
                                if potential_parent['node_id'] not in node['parent_nodes']:
                                    node['parent_nodes'].append(potential_parent['node_id'])
                                if node['node_id'] not in potential_parent['child_nodes']:
                                    potential_parent['child_nodes'].append(node['node_id'])
        
        return nodes

    def validate_dag_structure(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate that the graph is acyclic and follows campaign logic rules"""
        
        # Build adjacency list
        adj = {node['node_id']: node['child_nodes'] for node in nodes}
        
        # Check for cycles using iterative DFS to avoid recursion
        def has_cycle_iterative():
            visited = set()
            recursion_stack = set()
            
            # Use stack for iterative DFS
            for start_node in nodes:
                if start_node['node_id'] in visited:
                    continue
                
                stack = [(start_node['node_id'], False)]  # (node_id, is_processing)
                
                while stack:
                    node_id, is_processing = stack.pop()
                    
                    if is_processing:
                        recursion_stack.remove(node_id)
                        continue
                    
                    if node_id in visited:
                        continue
                    
                    if node_id in recursion_stack:
                        return True, [node_id]  # Cycle detected
                    
                    visited.add(node_id)
                    recursion_stack.add(node_id)
                    
                    # Push processing marker
                    stack.append((node_id, True))
                    
                    # Push children
                    for child_id in adj[node_id]:
                        if child_id not in visited:
                            stack.append((child_id, False))
            
            return False, []
        
        has_cycle, cycle_nodes = has_cycle_iterative()
        
        # Create node lookup by technique_id and node_id
        node_by_id = {node['node_id']: node for node in nodes}
        
        # Additional validation rules
        validation_results = {
            "is_dag": not has_cycle,
            "cycle_detected": has_cycle,
            "cycle_nodes": cycle_nodes if has_cycle else [],
            "validation_rules": {
                "impact_nodes_have_upstream": True,
                "initial_access_has_no_parents": True,
                "execution_nodes_have_path": True,
                "all_nodes_reachable": True,
                "no_dangling_nodes": True,
                "prerequisites_satisfiable": True
            },
            "violations": []
        }
        
        # Rule 1: Impact nodes must have at least one upstream execution node
        for node in nodes:
            if 'impact' in node['tactic'].lower():
                has_execution_upstream = False
                # Check all ancestors for execution nodes
                visited_ancestors = set()
                stack = list(node['parent_nodes'])
                
                while stack:
                    ancestor_id = stack.pop()
                    if ancestor_id in visited_ancestors:
                        continue
                    visited_ancestors.add(ancestor_id)
                    
                    if ancestor_id in node_by_id:
                        ancestor = node_by_id[ancestor_id]
                        if 'execution' in ancestor['tactic'].lower():
                            has_execution_upstream = True
                            break
                        # Add its parents to stack
                        stack.extend(ancestor.get('parent_nodes', []))
                
                if not has_execution_upstream:
                    validation_results["validation_rules"]["impact_nodes_have_upstream"] = False
                    validation_results["violations"].append({
                        "node": node['technique_id'],
                        "node_id": node['node_id'],
                        "rule": "impact_nodes_have_upstream",
                        "message": f"Impact node {node['technique_id']} has no execution node upstream"
                    })
        
        # Rule 2: Initial Access nodes should have no parents (be root nodes)
        for node in nodes:
            if 'initial-access' in node['tactic'].lower() or 'initial access' in node['tactic'].lower():
                if node['parent_nodes']:
                    validation_results["validation_rules"]["initial_access_has_no_parents"] = False
                    validation_results["violations"].append({
                        "node": node['technique_id'],
                        "node_id": node['node_id'],
                        "rule": "initial_access_has_no_parents",
                        "message": f"Initial Access node {node['technique_id']} has parent nodes"
                    })
        
        # Rule 3: Every execution node must have a path from an initial access node
        for node in nodes:
            if 'execution' in node['tactic'].lower():
                has_path_from_initial = False
                visited_ancestors = set()
                stack = list(node['parent_nodes'])
                
                while stack:
                    ancestor_id = stack.pop()
                    if ancestor_id in visited_ancestors:
                        continue
                    visited_ancestors.add(ancestor_id)
                    
                    if ancestor_id in node_by_id:
                        ancestor = node_by_id[ancestor_id]
                        if 'initial-access' in ancestor['tactic'].lower():
                            has_path_from_initial = True
                            break
                        stack.extend(ancestor.get('parent_nodes', []))
                
                # Also check if node itself is initial access
                if 'initial-access' in node['tactic'].lower():
                    has_path_from_initial = True
                
                if not has_path_from_initial and node['parent_nodes']:  # Only enforce for nodes with parents
                    validation_results["validation_rules"]["execution_nodes_have_path"] = False
                    validation_results["violations"].append({
                        "node": node['technique_id'],
                        "node_id": node['node_id'],
                        "rule": "execution_nodes_have_path",
                        "message": f"Execution node {node['technique_id']} has no path from an Initial Access node"
                    })
        
        # Rule 4: All nodes must be reachable from at least one root
        root_nodes = [node for node in nodes if not node['parent_nodes']]
        reachable_nodes = set()
        
        # BFS from all roots
        queue = deque([node['node_id'] for node in root_nodes])
        
        while queue:
            current_id = queue.popleft()
            if current_id in reachable_nodes:
                continue
            reachable_nodes.add(current_id)
            
            if current_id in node_by_id:
                queue.extend(node_by_id[current_id].get('child_nodes', []))
        
        for node in nodes:
            if node['node_id'] not in reachable_nodes:
                validation_results["validation_rules"]["all_nodes_reachable"] = False
                validation_results["violations"].append({
                    "node": node['technique_id'],
                    "node_id": node['node_id'],
                    "rule": "all_nodes_reachable",
                    "message": f"Node {node['technique_id']} is not reachable from any root node"
                })
        
        # Rule 5: No dangling nodes (nodes with children that don't exist)
        all_node_ids = set(node['node_id'] for node in nodes)
        for node in nodes:
            for child_id in node['child_nodes']:
                if child_id not in all_node_ids:
                    validation_results["validation_rules"]["no_dangling_nodes"] = False
                    validation_results["violations"].append({
                        "node": node['technique_id'],
                        "node_id": node['node_id'],
                        "rule": "no_dangling_nodes",
                        "message": f"Node {node['technique_id']} references non-existent child {child_id}"
                    })
            for parent_id in node['parent_nodes']:
                if parent_id not in all_node_ids:
                    validation_results["validation_rules"]["no_dangling_nodes"] = False
                    validation_results["violations"].append({
                        "node": node['technique_id'],
                        "node_id": node['node_id'],
                        "rule": "no_dangling_nodes",
                        "message": f"Node {node['technique_id']} references non-existent parent {parent_id}"
                    })
        
        # Rule 6: Prerequisites must be satisfiable by some node in the graph
        all_provides = set()
        for node in nodes:
            all_provides.update(node['provides'])
        
        for node in nodes:
            for prereq in node['required_prerequisites']:
                # Check if this prerequisite can be satisfied by any node's provides
                prereq_satisfiable = False
                for provide in all_provides:
                    if prereq in provide or provide in prereq:
                        prereq_satisfiable = True
                        break
                
                if not prereq_satisfiable and prereq not in node.get('satisfied_prerequisites', []):
                    validation_results["validation_rules"]["prerequisites_satisfiable"] = False
                    validation_results["violations"].append({
                        "node": node['technique_id'],
                        "node_id": node['node_id'],
                        "rule": "prerequisites_satisfiable",
                        "message": f"Prerequisite '{prereq}' for node {node['technique_id']} cannot be satisfied by any node in the graph"
                    })
        
        return validation_results

    def generate_dag_representation(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a DAG representation using technique_id as node identification"""
        
        # Create a mapping from node_id to technique_id for lookup
        node_id_to_tech = {node['node_id']: node['technique_id'] for node in nodes}
        
        # Build the DAG using technique_ids as node identifiers
        dag = {
            "nodes": [],
            "edges": [],
            "levels": {},
            "adjacency_list": {},
            "roots": [],
            "leaves": []
        }
        
        # Collect all unique technique_ids (there might be multiple nodes with same technique_id)
        tech_id_counts = defaultdict(int)
        for node in nodes:
            tech_id_counts[node['technique_id']] += 1
        
        # Create node entries with technique_id and index if multiple
        for node in nodes:
            tech_id = node['technique_id']
            if tech_id_counts[tech_id] > 1:
                # Multiple nodes with same technique_id, add index
                node_label = f"{tech_id}_{node['node_index']}"
            else:
                node_label = tech_id
            
            dag["nodes"].append({
                "id": node_label,
                "original_id": node['node_id'],
                "technique_id": tech_id,
                "technique_name": node['technique_name'],
                "tactic": node['tactic'],
                "index": node['node_index'],
                "provides": node['provides'],
                "prerequisites": node['required_prerequisites']
            })
        
        # Build edges using technique_id references
        for node in nodes:
            source_tech = node['technique_id']
            if tech_id_counts[source_tech] > 1:
                source_label = f"{source_tech}_{node['node_index']}"
            else:
                source_label = source_tech
            
            for child_id in node['child_nodes']:
                if child_id in node_id_to_tech:
                    target_tech = node_id_to_tech[child_id]
                    if tech_id_counts[target_tech] > 1:
                        # Need to find which index this child_id corresponds to
                        for n in nodes:
                            if n['node_id'] == child_id:
                                target_label = f"{target_tech}_{n['node_index']}"
                                break
                        else:
                            target_label = target_tech
                    else:
                        target_label = target_tech
                    
                    dag["edges"].append({
                        "from": source_label,
                        "to": target_label
                    })
        
        # Build adjacency list
        for node in dag["nodes"]:
            dag["adjacency_list"][node["id"]] = {
                "parents": [],
                "children": []
            }
        
        for edge in dag["edges"]:
            if edge["to"] in dag["adjacency_list"]:
                dag["adjacency_list"][edge["to"]]["parents"].append(edge["from"])
            if edge["from"] in dag["adjacency_list"]:
                dag["adjacency_list"][edge["from"]]["children"].append(edge["to"])
        
        # Find roots (nodes with no parents)
        dag["roots"] = [node_id for node_id, adj in dag["adjacency_list"].items() if not adj["parents"]]
        
        # Find leaves (nodes with no children)
        dag["leaves"] = [node_id for node_id, adj in dag["adjacency_list"].items() if not adj["children"]]
        
        # Calculate levels (topological generations)
        if dag["roots"]:
            # BFS to assign levels
            queue = deque([(root, 0) for root in dag["roots"]])
            visited = set()
            
            while queue:
                node_id, level = queue.popleft()
                if node_id in visited:
                    continue
                visited.add(node_id)
                
                if level not in dag["levels"]:
                    dag["levels"][level] = []
                dag["levels"][level].append(node_id)
                
                for child in dag["adjacency_list"][node_id]["children"]:
                    queue.append((child, level + 1))
        
        return dag

    def print_dag_representation(self, dag: Dict[str, Any]):
        """Print a visual representation of the DAG"""
        print("\n" + "="*100)
        print("📊 DAG REPRESENTATION (using technique_ids)")
        print("="*100)
        
        print(f"\n📌 Nodes ({len(dag['nodes'])}):")
        for node in dag["nodes"]:
            print(f"  • {node['id']}: {node['technique_name']} [{node['tactic']}]")
        
        print(f"\n🔗 Edges ({len(dag['edges'])}):")
        for edge in dag["edges"]:
            print(f"  • {edge['from']} → {edge['to']}")
        
        print(f"\n🌳 Roots: {', '.join(dag['roots']) if dag['roots'] else 'None'}")
        print(f"🍃 Leaves: {', '.join(dag['leaves']) if dag['leaves'] else 'None'}")
        
        print(f"\n📈 Execution Levels:")
        for level in sorted(dag["levels"].keys()):
            print(f"  Level {level}: {', '.join(dag['levels'][level])}")
        
        # ASCII DAG visualization
        print("\n" + "="*100)
        print("📈 ASCII DAG VISUALIZATION")
        print("="*100)
        
        # Simple tree-like visualization using iterative approach to avoid recursion
        def print_tree_iterative():
            visited = set()
            stack = []
            
            # Push roots with their state
            for i, root in enumerate(dag["roots"]):
                is_last = (i == len(dag["roots"]) - 1)
                stack.append((root, "", is_last, False))
            
            while stack:
                node_id, prefix, is_last, visited_flag = stack.pop()
                
                if visited_flag:
                    # This is the post-processing marker
                    if node_id in visited:
                        visited.remove(node_id)
                    continue
                
                if node_id in visited:
                    # Node already visited, show reference
                    print(f"{prefix}{'└── ' if is_last else '├── '}{node_id} (already shown)")
                    continue
                
                # Mark as visited
                visited.add(node_id)
                
                # Print current node
                print(f"{prefix}{'└── ' if is_last else '├── '}{node_id}")
                
                # Push post-processing marker
                stack.append((node_id, prefix, is_last, True))
                
                # Prepare children
                children = dag["adjacency_list"][node_id]["children"]
                if children:
                    new_prefix = prefix + ("    " if is_last else "│   ")
                    # Push children in reverse order to maintain visual order
                    for i, child in enumerate(reversed(children)):
                        is_last_child = (i == 0)  # Since we're reversed, first in reversed is last in original
                        stack.append((child, new_prefix, is_last_child, False))
        
        print("\nDAG Structure:")
        print_tree_iterative()

    def create_operation(self, campaign_name: str) -> str:
        """Create a new operation in Caldera"""
        # Get first three letters of campaign name
        prefix = campaign_name[:3].upper()
        
        # Find the next available operation number
        operation_name = f"{prefix}{self.operation_number:02d}"
        
        # Check if operation already exists
        result = subprocess.run(
            [sys.executable, "lib/operation.py", "list"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode == 0:
            # Parse the output to find existing operations
            existing_ops = re.findall(rf"{prefix}\d{{2}}", result.stdout)
            if existing_ops:
                # Find the highest number and increment
                max_num = 0
                for op in existing_ops:
                    num = int(op[3:5])
                    if num > max_num:
                        max_num = num
                self.operation_number = max_num + 1
                operation_name = f"{prefix}{self.operation_number:02d}"
        
        # Create the operation
        print(f"\n🔄 Creating operation: {operation_name}")
        result = subprocess.run(
            [sys.executable, "lib/operation.py", "--name", operation_name, "create", "--group", "red"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode == 0:
            print(f"✅ Operation {operation_name} created successfully")
            return operation_name
        else:
            print(f"❌ Failed to create operation: {result.stderr}")
            return None

    def parse_llm_response_and_populate_commands(self, llm_response: str, node: Dict[str, Any]):
        """Parse LLM response and populate node's environment_setup_commands and attacker_commands"""
        
        if not llm_response:
            print(f"  ⚠️  Empty response from LLM")
            return
        
        # Parse ENVIRONMENT_SETUP_COMMANDS section
        if "ENVIRONMENT_SETUP_COMMANDS:" in llm_response:
            setup_section = llm_response.split("ENVIRONMENT_SETUP_COMMANDS:")[1]
            if "ATTACKER_COMMANDS:" in setup_section:
                setup_section = setup_section.split("ATTACKER_COMMANDS:")[0]
            
            # Extract commands using SETUP_CMD pattern
            setup_lines = setup_section.split('\n')
            current_cmd = None
            current_desc = None
            
            for line in setup_lines:
                line = line.strip()
                if line.startswith('SETUP_CMD:'):
                    if current_cmd:
                        # Save previous command
                        node['environment_setup_commands'].append(current_cmd)
                    current_cmd = line.replace('SETUP_CMD:', '').strip()
                    current_desc = None
                elif line.startswith('SETUP_DESC:'):
                    current_desc = line.replace('SETUP_DESC:', '').strip()
                elif current_cmd and not line.startswith('SETUP_') and not line.startswith('ATTACK_'):
                    # Multi-line command continuation
                    current_cmd += '\n' + line
            
            # Save last command
            if current_cmd:
                node['environment_setup_commands'].append(current_cmd)
        else:
            print(f"  ⚠️  No ENVIRONMENT_SETUP_COMMANDS section found in response")
        
        # Parse ATTACKER_COMMANDS section
        if "ATTACKER_COMMANDS:" in llm_response:
            attack_section = llm_response.split("ATTACKER_COMMANDS:")[1]
            
            # Extract commands using ATTACK_CMD pattern
            attack_lines = attack_section.split('\n')
            current_cmd = None
            current_desc = None
            
            for line in attack_lines:
                line = line.strip()
                if line.startswith('ATTACK_CMD:'):
                    if current_cmd:
                        # Save previous command
                        node['attacker_commands'].append(current_cmd)
                    current_cmd = line.replace('ATTACK_CMD:', '').strip()
                    current_desc = None
                elif line.startswith('ATTACK_DESC:'):
                    current_desc = line.replace('ATTACK_DESC:', '').strip()
                elif current_cmd and not line.startswith('SETUP_') and not line.startswith('ATTACK_'):
                    # Multi-line command continuation
                    current_cmd += '\n' + line
            
            # Save last command
            if current_cmd:
                node['attacker_commands'].append(current_cmd)
        else:
            print(f"  ⚠️  No ATTACKER_COMMANDS section found in response")

    def generate_commands_with_llm(self, rag: Dict[str, Any]) -> bool:
        """Generate commands for all nodes using Anthropic or Azure OpenAI API"""
        
        # Check which API to use - Azure takes priority if configured
        azure_key = getattr(config, 'AZURE_SECRET_KEY', None)
        azure_endpoint = getattr(config, 'AZURE_ENDPOINT', None)
        azure_deployment = getattr(config, 'AZURE_DEPLOYMENT', None)
        anthropic_key = getattr(config, 'ANTHROPIC_SECRET_KEY', None)
        
        use_azure = False
        use_anthropic = False
        
        # Check if Azure is partially configured
        if azure_key and not azure_endpoint:
            print("⚠️  AZURE_SECRET_KEY found but AZURE_ENDPOINT is missing")
            print("   Add to config.py:")
            print("   AZURE_ENDPOINT = 'https://your-resource.openai.azure.com/'")
            print("   AZURE_DEPLOYMENT = 'gpt-4'  # Optional")
            print()
            # Fall through to check Anthropic
        elif not azure_key and azure_endpoint:
            print("⚠️  AZURE_ENDPOINT found but AZURE_SECRET_KEY is missing")
            print("   Add to config.py:")
            print("   AZURE_SECRET_KEY = 'your-api-key'")
            print()
            # Fall through to check Anthropic
        
        # Determine which service to use
        if azure_key and azure_endpoint:
            if not AZURE_AVAILABLE:
                print("❌ Azure OpenAI configured but library not installed")
                print("   Install with: pip install openai")
                return False
            use_azure = True
            print("🔵 Using Azure OpenAI API")
        elif anthropic_key:
            if not ANTHROPIC_AVAILABLE:
                print("❌ Anthropic configured but library not installed")
                print("   Install with: pip install anthropic")
                return False
            use_anthropic = True
            print("🟣 Using Anthropic Claude API")
        else:
            print("❌ No complete API configuration found")
            print()
            print("   Option 1 - Azure OpenAI:")
            print("   AZURE_SECRET_KEY = 'your-api-key'")
            print("   AZURE_ENDPOINT = 'https://your-resource.openai.azure.com/'")
            print("   AZURE_DEPLOYMENT = 'gpt-4'  # Optional")
            print()
            print("   Option 2 - Anthropic Claude:")
            print("   ANTHROPIC_SECRET_KEY = 'sk-ant-...'")
            print()
            print("   Current status:")
            print(f"   AZURE_SECRET_KEY: {'✓ Found' if azure_key else '✗ Missing'}")
            print(f"   AZURE_ENDPOINT: {'✓ Found' if azure_endpoint else '✗ Missing'}")
            print(f"   ANTHROPIC_SECRET_KEY: {'✓ Found' if anthropic_key else '✗ Missing'}")
            return False
        
        # Initialize the appropriate client
        if use_azure:
            # Clean up Azure credentials
            azure_key = str(azure_key).strip().strip('"').strip("'")
            azure_endpoint = str(azure_endpoint).strip().strip('"').strip("'")
            
            # Use deployment name from config or default to gpt-4
            if azure_deployment:
                deployment_name = str(azure_deployment).strip().strip('"').strip("'")
            else:
                deployment_name = "gpt-4"
            
            print(f"✓ Azure endpoint: {azure_endpoint}")
            print(f"✓ Using deployment: {deployment_name}")
            
            try:
                client = AzureOpenAI(
                    api_key=azure_key,
                    api_version="2024-02-15-preview",
                    azure_endpoint=azure_endpoint
                )
            except Exception as e:
                print(f"❌ Error initializing Azure OpenAI client: {e}")
                return False
        
        elif use_anthropic:
            # Clean up Anthropic API key
            anthropic_key = str(anthropic_key).strip().strip('"').strip("'")
            
            # Validate API key format
            if not anthropic_key.startswith('sk-ant-'):
                print(f"❌ Invalid Anthropic API key format")
                print(f"   API key should start with 'sk-ant-'")
                print(f"   Current key starts with: {anthropic_key[:10]}...")
                return False
            
            print(f"✓ API key found (length: {len(anthropic_key)} chars)")
            
            try:
                client = anthropic.Anthropic(api_key=anthropic_key)
            except Exception as e:
                print(f"❌ Error initializing Anthropic client: {e}")
                return False
        
        # Find nodes that need command generation
        nodes_needing_commands = [
            node for node in rag['structural_nodes']
            if not node.get('attacker_commands') or not node.get('environment_setup_commands')
        ]
        
        if not nodes_needing_commands:
            print("\n✅ All nodes already have commands generated")
            return True
        
        print(f"\n🤖 Generating commands for {len(nodes_needing_commands)} nodes...")
        print("="*100)
        
        for i, node in enumerate(nodes_needing_commands, 1):
            print(f"\n[{i}/{len(nodes_needing_commands)}] Generating commands for: {node['technique_id']} - {node['technique_name']}")
            
            # Get the AI prompt template
            prompt = node.get('ai_prompt_template', '')
            if not prompt:
                print(f"  ⚠️  No AI prompt template found, skipping...")
                continue
            
            # Add progressive delay before first try to avoid rate limiting
            # Pattern: 5s, 10s, 15s, 20s, 5s, 10s, 15s, 20s, ...
            delay_pattern = [5, 10, 15, 20]
            initial_delay = delay_pattern[(i - 1) % 4]
            
            if i > 1:  # Don't delay before first node
                print(f"  ⏱️  Waiting {initial_delay} seconds before API call...")
                time.sleep(initial_delay)
            
            try:
                print(f"  🔄 Calling LLM API...")
                
                response_text = None
                max_retries = 3
                retry_delay = 2
                
                for attempt in range(max_retries):
                    try:
                        if use_azure:
                            # Call Azure OpenAI API
                            response = client.chat.completions.create(
                                model=deployment_name,
                                messages=[
                                    {"role": "system", "content": "You are a cybersecurity expert helping to generate attack simulation commands."},
                                    {"role": "user", "content": prompt}
                                ],
                                max_tokens=2000,
                                temperature=0.7
                            )
                            response_text = response.choices[0].message.content
                        
                        elif use_anthropic:
                            # Call Anthropic API
                            message = client.messages.create(
                                model="claude-sonnet-4-20250514",
                                max_tokens=2000,
                                messages=[
                                    {"role": "user", "content": prompt}
                                ]
                            )
                            response_text = message.content[0].text
                        
                        # Check if we got a valid response
                        if response_text and len(response_text.strip()) > 0:
                            break
                        else:
                            print(f"  ⚠️  Empty response on attempt {attempt + 1}/{max_retries}")
                            if attempt < max_retries - 1:
                                print(f"     Retrying in {retry_delay} seconds...")
                                time.sleep(retry_delay)
                                retry_delay *= 2  # Exponential backoff
                    
                    except Exception as api_error:
                        print(f"  ⚠️  API error on attempt {attempt + 1}/{max_retries}: {api_error}")
                        if attempt < max_retries - 1:
                            print(f"     Retrying in {retry_delay} seconds...")
                            time.sleep(retry_delay)
                            retry_delay *= 2
                        else:
                            raise
                
                # Check if we got a response after all retries
                if not response_text or len(response_text.strip()) == 0:
                    print(f"  ❌ Failed to get valid response after {max_retries} attempts")
                    print(f"     Skipping this node...")
                    continue
                
                # Parse and populate commands
                self.parse_llm_response_and_populate_commands(response_text, node)
                
                # Show results
                setup_count = len(node.get('environment_setup_commands', []))
                attack_count = len(node.get('attacker_commands', []))
                
                if setup_count == 0 and attack_count == 0:
                    print(f"  ⚠️  No commands were parsed from LLM response")
                    if response_text:
                        print(f"     Response preview: {response_text[:200]}...")
                else:
                    print(f"  ✅ Generated {setup_count} setup commands, {attack_count} attack commands")
                    
                    if setup_count > 0:
                        print(f"     Setup: {node['environment_setup_commands'][0][:60]}...")
                    if attack_count > 0:
                        print(f"     Attack: {node['attacker_commands'][0][:60]}...")
                
            except Exception as e:
                print(f"  ❌ Error generating commands: {e}")
                print(f"     Skipping this node...")
                continue
        
        print("\n" + "="*100)
        print("✅ Command generation complete!")
        return True

    def execute_command(self, operation_name: str, node: Dict[str, Any]) -> bool:
        """Execute commands for a node in the operation - UPDATED for dual commands"""
        # First, execute environment setup commands on target
        if node.get('environment_setup_commands'):
            print(f"  🔧 Running environment setup commands on {node['target_host_type']}...")
            for i, cmd in enumerate(node['environment_setup_commands'], 1):
                print(f"     [{i}] {cmd[:80]}...")
                # Execute on target - would need to specify target host to Caldera
                # For now, just simulating
        
        # Then, execute attacker commands from Kali
        if not node.get('attacker_commands'):
            print(f"  ⚠️  No attacker commands to execute for {node['technique_id']}")
            return False
        
        print(f"  ⚔️  Running attacker commands from Kali...")
        for i, command in enumerate(node['attacker_commands'], 1):
            print(f"     [{i}] Executing: {command[:100]}...")
            
            try:
                # Build the command list
                cmd_parts = [
                    sys.executable,
                    "lib/command.py",
                    operation_name,
                    command
                ]
                
                result = subprocess.run(
                    cmd_parts,
                    capture_output=True,
                    text=True,
                    cwd=project_root,
                    timeout=120
                )
                
                if result.stdout:
                    print(f"     Output: {result.stdout[:200]}")
                if result.stderr:
                    print(f"     Error: {result.stderr[:200]}")
                
                if result.returncode != 0:
                    print(f"  ❌ Command {i} failed with return code {result.returncode}")
                    node['execution_result'] = {
                        "success": False,
                        "error": result.stderr,
                        "output": result.stdout,
                        "returncode": result.returncode,
                        "timestamp": datetime.now().isoformat()
                    }
                    return False
                    
            except subprocess.TimeoutExpired:
                print(f"  ❌ Command {i} timed out")
                node['execution_result'] = {
                    "success": False,
                    "error": "Command timed out after 120 seconds",
                    "timestamp": datetime.now().isoformat()
                }
                return False
            except Exception as e:
                print(f"  ❌ Error executing command {i}: {e}")
                node['execution_result'] = {
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                return False
        
        # If we got here, all commands succeeded
        print(f"  ✅ All commands executed successfully")
        node['executed'] = True
        node['execution_result'] = {
            "success": True,
            "output": "All commands completed",
            "timestamp": datetime.now().isoformat()
        }
        
        # Try to parse command output for any useful information
        if result.stdout:
            self.parse_command_output(node, result.stdout)
        
        return True

    def parse_command_output(self, node: Dict[str, Any], output: str):
        """Parse command output for useful information"""
        if not output:
            return
        
        # Look for potential IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, output)
        if ips:
            print(f"     Discovered IPs: {', '.join(ips[:3])}")
            node['discovered_ips'] = ips
        
        # Look for potential hostnames
        hostname_pattern = r'\b([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.)+[a-zA-Z]{2,}\b'
        hostnames = re.findall(hostname_pattern, output)
        if hostnames:
            print(f"     Discovered hostnames: {', '.join(hostnames[:3])}")
            node['discovered_hostnames'] = hostnames
        
        # Look for potential usernames
        username_pattern = r'\b(?:user|username|account):\s*(\w+)\b'
        usernames = re.findall(username_pattern, output.lower())
        if usernames:
            print(f"     Discovered usernames: {', '.join(usernames[:3])}")
            node['discovered_usernames'] = usernames

    def execute_dag(self, dag: Dict[str, Any], structural_nodes: List[Dict[str, Any]], campaign_name: str):
        """Execute the DAG by finding the first unexecuted node in topological order"""
        
        print("\n" + "="*100)
        print("🚀 EXECUTING CAMPAIGN DAG")
        print("="*100)
        
        # Create operation
        operation_name = self.create_operation(campaign_name)
        if not operation_name:
            print("❌ Cannot proceed without an operation")
            return
        
        # Get execution order from levels (flattened)
        levels = dag.get('levels', {})
        execution_order = []
        for level in sorted(levels.keys()):
            execution_order.extend(levels[level])
        
        node_by_id = {node['node_id']: node for node in structural_nodes}
        node_by_label = {}
        
        # Create mapping from node label to structural node
        for node in structural_nodes:
            # Find the corresponding label from dag nodes
            for dag_node in dag['nodes']:
                if dag_node['original_id'] == node['node_id']:
                    node_by_label[dag_node['id']] = node
                    break
        
        # Track execution status
        execution_log = []
        
        # Execute nodes in order (no prerequisite checks)
        for position, node_label in enumerate(execution_order, 1):
            target_node = node_by_label.get(node_label)
            
            if not target_node:
                print(f"⚠️  Could not find node for label: {node_label}")
                continue
            
            # Check if this node has already been executed
            if target_node.get('executed', False):
                print(f"\n⏭️  Node {target_node['technique_id']} already executed, skipping...")
                continue
            
            print(f"\n{'='*60}")
            print(f"📌 Step {position}/{len(execution_order)}: {target_node['technique_id']} - {target_node['technique_name']}")
            print(f"{'='*60}")
            
            # Check if we have commands
            if not target_node.get('attacker_commands'):
                print(f"  ⚠️  No attacker commands available for this node")
                print(f"  💡 You need to generate commands using an LLM call first")
                continue
            
            # Execute the command
            print(f"\n  ▶️  Executing node: {target_node['technique_id']}")
            success = self.execute_command(operation_name, target_node)
            
            execution_log.append({
                "node": target_node['technique_id'],
                "node_name": target_node['technique_name'],
                "node_label": node_label,
                "position": position,
                "success": success,
                "setup_cmds": len(target_node.get('environment_setup_commands', [])),
                "attack_cmds": len(target_node.get('attacker_commands', [])),
                "timestamp": datetime.now().isoformat()
            })
            
            if success:
                print(f"  ✅ Node {target_node['technique_id']} executed successfully")
            else:
                print(f"  ❌ Node {target_node['technique_id']} execution failed")
                # Stop on failure
                print(f"  ⏸️  Stopping execution due to failure")
                break
            
            # Small delay before next execution
            if position < len(execution_order):
                print(f"\n⏱️  Preparing next node...")
                time.sleep(2)
        
        # Print execution summary
        print("\n" + "="*100)
        print("📊 EXECUTION SUMMARY")
        print("="*100)
        
        if execution_log:
            successful = sum(1 for entry in execution_log if entry['success'])
            failed = len(execution_log) - successful
            
            print(f"\n✅ Executed nodes: {len(execution_log)}")
            print(f"   • Successful: {successful}")
            print(f"   • Failed: {failed}")
            
            print(f"\n📋 Execution Log:")
            for entry in execution_log:
                status = "✅" if entry['success'] else "❌"
                print(f"\n  {status} [{entry['position']}] {entry['node']} - {entry['node_name']}")
                print(f"     Setup cmds: {entry['setup_cmds']}, Attack cmds: {entry['attack_cmds']}")
            
            # Show all outputs
            print(f"\n📄 Command Outputs:")
            for node in structural_nodes:
                if node.get('executed', False) and node.get('execution_result'):
                    result = node['execution_result']
                    print(f"\n  {node['technique_id']}:")
                    if result.get('output'):
                        print(f"    Output: {result['output'][:500]}")
                    if result.get('error') and not result.get('success'):
                        print(f"    Error: {result['error'][:500]}")
            
            executed_count = len([n for n in structural_nodes if n.get('executed', False)])
            if executed_count == len(structural_nodes):
                print(f"\n✅ All {len(structural_nodes)} nodes executed successfully!")
            else:
                print(f"\n⏸️  Executed {executed_count}/{len(structural_nodes)} nodes")
        else:
            print("\n❌ No nodes were executed")

    def analyze_capability_flow(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how capabilities flow through the DAG"""
        capability_flow = {
            "initial_capabilities": [],
            "final_capabilities": [],
            "capability_chain": []
        }
        
        if not nodes:
            return capability_flow
        
        # Initial capabilities (from first node)
        if nodes:
            capability_flow["initial_capabilities"] = nodes[0].get('provides', [])
        
        # Final capabilities (cumulative from all nodes)
        all_capabilities = set()
        for node in nodes:
            all_capabilities.update(node.get('provides', []))
        capability_flow["final_capabilities"] = list(all_capabilities)
        
        # Capability chain (how capabilities accumulate)
        current_capabilities = set()
        for node in nodes:
            current_capabilities.update(node.get('provides', []))
            capability_flow["capability_chain"].append({
                "node_index": node['node_index'],
                "technique": f"{node['technique_id']} - {node['technique_name']}",
                "adds": node.get('provides', []),
                "cumulative_capabilities": list(current_capabilities)
            })
        
        return capability_flow

    def extract_edges(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Extract edges from node relationships"""
        edges = []
        for node in nodes:
            for child_id in node['child_nodes']:
                edges.append({
                    "from": node['node_id'],
                    "to": child_id
                })
        return edges

    def save_rag(self, rag: Dict[str, Any], campaign_name: str):
        """Save RAG structure to file"""
        output_dir = project_root / "data" / "dag"
        output_dir.mkdir(exist_ok=True, parents=True)
        
        output_file = output_dir / f"{campaign_name}_dag.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(rag, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ DAG saved to: {output_file}")
        return output_file

    def print_rag_summary(self, rag: Dict[str, Any]):
        """Print summary of RAG structure"""
        print("\n" + "="*100)
        print("📊 RAG STRUCTURE SUMMARY")
        print("="*100)
        
        print(f"\n📌 Campaign: {rag['campaign_name']}")
        print(f"   Generated: {rag['generated_at']}")
        print(f"   Total techniques: {rag['metadata']['total_techniques']}")
        print(f"   Nodes generated: {rag['metadata']['nodes_generated']}")
        print(f"   Is DAG: {rag['metadata']['validation']['is_dag']}")
        
        # Print DAG representation summary
        if 'dag_representation' in rag:
            dag = rag['dag_representation']
            print(f"\n📈 DAG Representation:")
            print(f"   Nodes: {len(dag['nodes'])}")
            print(f"   Edges: {len(dag['edges'])}")
            print(f"   Roots: {', '.join(dag['roots'])}")
            print(f"   Leaves: {', '.join(dag['leaves'])}")
            print(f"   Levels: {len(dag['levels'])}")
        
        print(f"\n🔧 STRUCTURAL NODES:")
        for i, node in enumerate(rag['structural_nodes'], 1):
            print(f"\n  {i}. {node['technique_id']} - {node['technique_name']}")
            print(f"     Node ID: {node['node_id'][:8]}...")
            print(f"     Tactic: {node['tactic']}")
            print(f"     Requires: {', '.join(node['required_prerequisites'][:3])}")
            if len(node['required_prerequisites']) > 3:
                print(f"              ... and {len(node['required_prerequisites'])-3} more")
            print(f"     Provides: {', '.join(node['provides'])}")
            print(f"     Satisfied: {len(node.get('satisfied_prerequisites', []))}/{len(node['required_prerequisites'])}")
            print(f"     Parents: {len(node['parent_nodes'])}")
            print(f"     Children: {len(node['child_nodes'])}")
            
            # Show command counts
            setup_cmds = len(node.get('environment_setup_commands', []))
            attack_cmds = len(node.get('attacker_commands', []))
            print(f"     Commands: {setup_cmds} setup, {attack_cmds} attack")
            
            if node['campaign_context']:
                print(f"     Context: {node['campaign_context'][:100]}...")
        
        print(f"\n🔗 EDGES ({len(rag['edges'])} dependencies):")
        for edge in rag['edges']:
            from_node = next((n for n in rag['structural_nodes'] if n['node_id'] == edge['from']), None)
            to_node = next((n for n in rag['structural_nodes'] if n['node_id'] == edge['to']), None)
            if from_node and to_node:
                print(f"  • {from_node['technique_id']} → {to_node['technique_id']}")
        
        if 'capability_flow' in rag:
            print(f"\n📈 CAPABILITY FLOW:")
            flow = rag['capability_flow']
            print(f"  Initial: {', '.join(flow['initial_capabilities'])}")
            print(f"  Final: {', '.join(flow['final_capabilities'])}")
            
            print(f"\n  Capability Chain:")
            for step in flow['capability_chain']:
                print(f"    Step {step['node_index']}: {step['technique']}")
                print(f"      + Adds: {', '.join(step['adds'])}")
        
        print("\n" + "="*100)

    def show_available_campaigns(self):
        """Show all available campaigns"""
        print("\n📋 Available campaigns:")
        campaign_files = sorted(self.campaigns_dir.glob("*.yml"))
        
        for filepath in campaign_files:
            name = filepath.stem
            if name.startswith('0.'):
                name = name[2:]
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    desc = data.get('description', '')[:60]
                    tech_count = len(data.get('atomic_ordering', []))
                    abilities_count = len(data.get('abilities', {}))
                    print(f"   • {name} - {desc}... ({tech_count} techniques, {abilities_count} abilities)")
            except (yaml.YAMLError, OSError, KeyError):
                print(f"   • {name}")

    def generate_rag(self, campaign_name: str) -> Dict[str, Any]:
        """Generate complete RAG structure for the campaign"""
        try:
            # Find and load campaign
            campaign_file = self.find_campaign_file(campaign_name)
            campaign = self.load_campaign(campaign_file)
            
            display_name = campaign.get('name', campaign_file.stem)
            if display_name.startswith('0.'):
                display_name = display_name[2:]
            
            print("\n" + "="*100)
            print(f"🎯 Generating RAG for: {display_name}")
            print("="*100)
            
            # Get techniques
            technique_ids = campaign.get('atomic_ordering', [])
            abilities = campaign.get('abilities', {})
            
            if not technique_ids:
                print("\n⚠️  No techniques found in this campaign")
                return None
            
            # Generate structural nodes for each technique
            structural_nodes = []
            available_capabilities = set()
            
            for idx, tech_id in enumerate(technique_ids):
                if tech_id in abilities:
                    technique_data = abilities[tech_id]
                    technique_info = self.extract_technique_info(technique_data, tech_id)
                    
                    # Generate node with current available capabilities
                    structural_node = self.generate_structural_node(technique_info, idx, available_capabilities)
                    structural_nodes.append(structural_node)
                    
                    # Update available capabilities for next nodes
                    available_capabilities.update(structural_node['provides'])
                    
                    print(f"\n  ✓ Generated node for: {technique_info['technique_id']} - {technique_info['technique_name']}")
                    print(f"     Provides: {', '.join(structural_node['provides'])}")
            
            # Build DAG relationships
            structural_nodes = self.build_dag_relationships(structural_nodes)
            
            # Validate DAG
            validation_results = self.validate_dag_structure(structural_nodes)
            
            # Generate DAG representation
            dag_representation = self.generate_dag_representation(structural_nodes)
            
            # Print validation results
            print("\n" + "="*100)
            print("🔍 DAG VALIDATION RESULTS")
            print("="*100)
            print(f"  Is DAG: {'✅' if validation_results['is_dag'] else '❌'} {validation_results['is_dag']}")
            if validation_results['cycle_detected']:
                print(f"  ⚠️  Cycle detected in graph!")
                if validation_results['cycle_nodes']:
                    cycle_tech_ids = []
                    for node_id in validation_results['cycle_nodes']:
                        for node in structural_nodes:
                            if node['node_id'] == node_id:
                                cycle_tech_ids.append(node['technique_id'])
                                break
                    print(f"     Cycle: {' → '.join(cycle_tech_ids)}")
            
            print("\n  Validation Rules:")
            for rule, passed in validation_results['validation_rules'].items():
                status = '✅' if passed else '❌'
                print(f"    {status} {rule.replace('_', ' ').title()}")
            
            if validation_results['violations']:
                print("\n  Violations:")
                for violation in validation_results['violations']:
                    print(f"    • {violation['message']}")
            
            # Print DAG representation
            self.print_dag_representation(dag_representation)
            
            # Create complete RAG structure
            rag = {
                "campaign_name": display_name,
                "campaign_file": str(campaign_file),
                "generated_at": datetime.now().isoformat(),
                "metadata": {
                    "total_techniques": len(technique_ids),
                    "nodes_generated": len(structural_nodes),
                    "validation": validation_results
                },
                "structural_nodes": structural_nodes,
                "dag_representation": dag_representation,
                "runtime_nodes": [],  # To be filled during execution
                "edges": self.extract_edges(structural_nodes),
                "capability_flow": self.analyze_capability_flow(structural_nodes)
            }
            
            return rag
            
        except FileNotFoundError as e:
            print(f"\n❌ {e}")
            return None
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return None

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(__doc__)
        viewer = CampaignRAGGenerator()
        viewer.show_available_campaigns()
        sys.exit(1)
    
    campaign_name = sys.argv[1].lower()
    generator = CampaignRAGGenerator()
    
    # Generate RAG
    rag = generator.generate_rag(campaign_name)
    
    if not rag:
        sys.exit(1)
    
    # Interactive menu loop
    while True:
        print("\n" + "="*100)
        print("⚡ CAMPAIGN MENU")
        print("="*100)
        print("   1. Show DAG summary")
        print("   2. Generate commands with LLM (fills environment_setup_commands and attacker_commands)")
        print("   3. Show full RAG structure (JSON)")
        print("   4. Validate prerequisite satisfaction")
        print("   5. Execute DAG on Caldera")
        print("   6. Save RAG to file")
        print("   7. Exit")
        
        choice = input("\n👉 Choose option (1-7): ").strip()
        
        if choice == '1':
            # Show DAG summary
            generator.print_rag_summary(rag)
            
        elif choice == '2':
            # Generate commands with LLM
            print("\n" + "="*100)
            print("🤖 LLM COMMAND GENERATION")
            print("="*100)
            print("This will use Claude to generate:")
            print("  • environment_setup_commands: Commands to run on target to create vulnerability")
            print("  • attacker_commands: Commands to run from Kali to exploit")
            print()
            
            confirm = input("Generate commands for all nodes? (y/n): ").lower()
            if confirm == 'y':
                success = generator.generate_commands_with_llm(rag)
                if success:
                    print("\n✅ Commands generated! Use option 1 to view updated DAG")
            
        elif choice == '3':
            # Show full RAG
            print("\n" + "="*100)
            print("📄 FULL RAG STRUCTURE (JSON)")
            print("="*100)
            print(json.dumps(rag, indent=2, ensure_ascii=False))
            
        elif choice == '4':
            # Validate prerequisites
            print("\n" + "="*100)
            print("🔍 PREREQUISITE VALIDATION")
            print("="*100)
            for node in rag['structural_nodes']:
                print(f"\n{node['technique_id']} - {node['technique_name']}:")
                
                if node.get('satisfied_prerequisites'):
                    print(f"  ✅ Satisfied: {', '.join(node['satisfied_prerequisites'])}")
                else:
                    print(f"  ✅ Satisfied: None")
                
                if node.get('unsatisfied_prerequisites'):
                    print(f"  ⚠️  Unsatisfied: {', '.join(node['unsatisfied_prerequisites'])}")
                else:
                    print(f"  ⚠️  Unsatisfied: None")
                
                # Show command status
                setup_count = len(node.get('environment_setup_commands', []))
                attack_count = len(node.get('attacker_commands', []))
                print(f"  📝 Commands: {setup_count} setup, {attack_count} attack")
            
        elif choice == '5':
            # Execute DAG
            print("\n" + "="*100)
            print("🚀 EXECUTE CAMPAIGN ON CALDERA")
            print("="*100)
            
            # Check if all nodes have commands
            nodes_without_commands = [
                node for node in rag['structural_nodes']
                if not node.get('attacker_commands')
            ]
            
            if nodes_without_commands:
                print(f"\n⚠️  Warning: {len(nodes_without_commands)} nodes don't have attacker commands:")
                for node in nodes_without_commands[:5]:
                    print(f"     • {node['technique_id']} - {node['technique_name']}")
                if len(nodes_without_commands) > 5:
                    print(f"     ... and {len(nodes_without_commands)-5} more")
                print("\n💡 Use option 2 to generate commands first")
                
                confirm = input("\nContinue anyway? (y/n): ").lower()
                if confirm != 'y':
                    continue
            
            print("\nThis will:")
            print("  1. Create a new operation in Caldera")
            print("  2. Execute environment setup commands on targets")
            print("  3. Execute attack commands from Kali")
            print("  4. Track execution results")
            
            confirm = input("\nProceed with execution? (y/n): ").lower()
            if confirm == 'y':
                generator.execute_dag(rag['dag_representation'], rag['structural_nodes'], campaign_name)
            
        elif choice == '6':
            # Save RAG
            generator.save_rag(rag, campaign_name)
            
        elif choice == '7':
            # Exit
            print("\n👋 Exiting...")
            break
            
        else:
            print("\n❌ Invalid option, please choose 1-7")

if __name__ == "__main__":
    main()
