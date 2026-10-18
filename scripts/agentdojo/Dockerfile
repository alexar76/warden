# AgentDojo + the compiled WARDEN flow guard. Build with network, run with --network none (gVisor on our hosts):
# the oracle needs none, and model.py talks to the model through files that relay.py, on the host, forwards.
# Pinned: agentdojo 0.1.35, benchmark suites v1.2.2.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir "agentdojo==0.1.35"
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /warden
COPY dist/ dist/
COPY scripts/agentdojo/ scripts/agentdojo/
RUN chown -R node /warden
USER node
ENTRYPOINT ["python3", "scripts/agentdojo/oracle.py"]
