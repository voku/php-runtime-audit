# Runtime patch guidance

Identify the runtime that serves the workload separately from installed packages and CLI PHP. Check package identity and the vendor's published security information for that exact distribution and package. Do not infer fixed or vulnerable status from an upstream version comparison when vendor backports are unknown. Record missing vendor evidence as unknown and keep patch status independent from compromise evidence.
