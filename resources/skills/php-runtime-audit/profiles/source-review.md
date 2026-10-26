# PHP source review guidance

Trace input from trust boundaries to sensitive operations such as deserialization, file access, process creation, and dynamic code paths. Cite concrete files and symbols, account for framework and PHP-version behavior, and distinguish reachable paths from theoretical patterns. Do not execute exploit payloads or treat a source-only review as a runtime audit.
