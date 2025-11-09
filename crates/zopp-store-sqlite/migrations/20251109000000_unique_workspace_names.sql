-- Make workspace names globally unique for better UX
CREATE UNIQUE INDEX idx_workspaces_name ON workspaces(name);
