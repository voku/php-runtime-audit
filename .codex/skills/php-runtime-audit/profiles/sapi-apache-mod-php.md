# Apache mod_php guidance

Apply Apache module guidance only when the supplied SAPI or configuration fact identifies mod_php. Keep this runtime separate from PHP-FPM services and CLI invocations. Missing module or virtual-host facts remain unknown.
