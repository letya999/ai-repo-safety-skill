export const AiRepoSafetyPlugin = async ({ $ }) => {
  const runProfile = async (command) => {
    if (!command) return
    await $`python .repo-safety/scripts/agent_hook_runner.py --profile sensitive-preflight --command ${command}`
  }

  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command = output?.args?.command || input?.args?.command || ""
      await runProfile(command)
    },
  }
}
