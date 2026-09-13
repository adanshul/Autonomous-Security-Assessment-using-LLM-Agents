# Contributing

Create a branch, install `.[dev,aws]`, and run Ruff, pytest and the demo before opening a pull request. Use synthetic fixtures only. New detectors need independent positive, negative, explicit-deny/conditional and scope-boundary cases. Preserve conservative unknown handling and do not allow planner output to bypass the verifier.

Document changes to schemas, finding keys, check coverage or benchmark definitions. Changes to finding units can invalidate longitudinal results. Keep original observations and adjudication separate; never edit a benchmark to manufacture a desired uplift.

Bug reports should include a synthetic snapshot, version, command, expected behavior and actual behavior. Do not attach customer policies, resource inventories or credentials publicly.
