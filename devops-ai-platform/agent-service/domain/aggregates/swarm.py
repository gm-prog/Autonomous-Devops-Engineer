from typing import List
from datetime import datetime
from ..entities.agent_instance import AgentInstance
from ..value_objects.agent_capability import AgentCapability

class SwarmAggregate:
    """
    Swarm Aggregate Root.
    Coordinates multiple, focused agent roles (e.g., Architect, Sentry, IaC Coder)
    to collectively solve system alerts or generate cloud infrastructure plans.
    """
    def __init__(self, id: str, mission_objective: str):
        self.id = id
        self.mission_objective = mission_objective
        self.launched_at = datetime.utcnow()
        self.agents: List[AgentInstance] = []
        self.status = "Forming" # Forming, Executing, MissionAccomplished, Failed

    def scale_up_role(self, agent: AgentInstance):
        if any(a.agent_id == agent.agent_id for a in self.agents):
            return
        self.agents.append(agent)

    def verify_mission_status(self) -> str:
        if not self.agents:
            self.status = "Failed"
            return self.status
            
        all_completed = all(a.status == "Completed" for a in self.agents)
        if all_completed:
            self.status = "MissionAccomplished"
        else:
            self.status = "Executing"
        return self.status
