# Isolated harness for running the Group B CVE MCP servers (safe subset).
# Vulnerable packages are installed at BUILD time (network available here);
# the container is then run with --network none so the servers run fully offline.
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv git ca-certificates && rm -rf /var/lib/apt/lists/*

# Each Python MCP server gets its OWN venv so their (conflicting) mcp SDK pins
# do not contaminate each other. excel-mcp-server==0.1.8 is the vulnerable pin.
RUN python3 -m venv /opt/excel && /opt/excel/bin/pip install --no-cache-dir \
      "excel-mcp-server==0.1.8" openpyxl || echo "EXCEL_INSTALL_FAIL"
RUN python3 -m venv /opt/git && /opt/git/bin/pip install --no-cache-dir \
      "mcp-server-git" || echo "GIT_INSTALL_FAIL"

# Node MCP servers (pinned to the vulnerable versions from the benchmark).
RUN npm install -g @modelcontextprotocol/server-filesystem@2025.3.28 || echo "FS_INSTALL_FAIL"
RUN npm install -g @modelcontextprotocol/server-memory || echo "MEM_INSTALL_FAIL"

# Record exactly what resolved, so the report can cite real installed versions.
RUN { echo '[excel venv]'; /opt/excel/bin/pip freeze 2>/dev/null | grep -iE 'excel|openpyxl|^mcp'; \
      echo '[git venv]';  /opt/git/bin/pip freeze 2>/dev/null | grep -iE 'mcp-server-git|^mcp'; } > /installed_py.txt; \
    (npm ls -g --depth=0 2>/dev/null || true) > /installed_npm.txt; true

COPY make_lab.py run_cve.py /app/
WORKDIR /app
CMD ["sh", "-c", "/opt/excel/bin/python /app/make_lab.py && python3 /app/run_cve.py exploit"]
