use crate::{
    config::beeline::{Config, Filter as CFilter, JwtFilter, LoadBalancer, MutateFilter, Policy},
    net::TryIntoRawOctets,
};
use std::{
    fs::{self, File},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Default, Clone, Debug)]
struct Filter {
    defs: String,
    code: String,
}

#[derive(Clone, Debug)]
struct Route {
    cond: String,
    filters: Vec<Filter>,
}

impl Filter {
    fn replace_defs<V: ToString>(&mut self, key: &str, value: V) {
        let key = format!("{{{}}}", key);
        self.defs = self.defs.replace(&key, &value.to_string());
    }

    fn replace_code<V: ToString>(&mut self, key: &str, value: V) {
        let key = format!("{{{}}}", key);
        self.code = self.code.replace(&key, &value.to_string());
    }
}

impl From<&str> for Filter {
    fn from(text: &str) -> Self {
        let segs = text.split("// ---").collect::<Vec<&str>>();

        Filter {
            defs: segs[0].into(),
            code: segs[1].into(),
        }
    }
}

pub struct Compiler {
    config: Config,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Variable {
    Buffer(String, String, Option<usize>),
    Range(String),
}

impl Variable {
    pub fn buffer(name: &str, ty: &str, size: Option<usize>) -> Self {
        Variable::Buffer(name.to_string(), ty.to_string(), size)
    }

    pub fn range(name: &str) -> Self {
        Variable::Range(name.to_string())
    }

    pub fn name(&self) -> &str {
        match self {
            Variable::Buffer(name, _, _) => name,
            Variable::Range(name) => name,
        }
    }

    pub fn is_buffer(&self) -> bool {
        match self {
            Variable::Buffer(_, _, _) => true,
            Variable::Range(_) => false,
        }
    }
}

fn sanitize_var_name(var: &str) -> String {
    var.replace("-", "_").to_lowercase()
}

impl Compiler {
    pub fn new(config: Config) -> Self {
        Compiler { config }
    }

    fn read_filter(&self, name: &str) -> Filter {
        let manifest_dir =
            std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
        let path = format!("src/bpf/filter/{}.bpf.c", name);
        let path = PathBuf::from(&manifest_dir).join(path);
        let filter = fs::read_to_string(&path)
            .expect(format!("Failed to find filter at {:?}", &path).as_str());
        Filter::from(filter.as_str())
    }

    fn generate_ctx(&self, vars: Vec<Variable>) -> Filter {
        let mut filter = self.read_filter("ctx");

        let var_defs = vars
            .iter()
            .map(|var| match &var {
                &Variable::Buffer(name, ty, size) => {
                    if ty == "char" {
                        format!(
                            "struct prange {name}_range;\nchar {name}[{size}];",
                            name = sanitize_var_name(name),
                            size = size.unwrap()
                        )
                    } else {
                        format!(
                            "struct prange {name}_range;\n{ty} {name};",
                            name = sanitize_var_name(name),
                            ty = ty
                        )
                    }
                }
                &Variable::Range(name) => {
                    format!("struct prange {}_range;", sanitize_var_name(name))
                }
            })
            .collect::<Vec<String>>()
            .join("\n");

        filter.replace_defs("vars", var_defs);

        let inits = vars
            .iter()
            .enumerate()
            .map(|(i, var)| {
                // TODO: let the initialization fail if len < size
                match &var {
                    &Variable::Buffer(name, ty, len) => {
                        let name = sanitize_var_name(name);
                        let code = if ty == "char" {
                            let mut mask = 1;
                            loop {
                                mask = mask << 1;
                                if (mask - 1) >= len.unwrap() {
                                    break;
                                }
                            }
                            let mask = mask - 1;

                            format!(
                                "r = pranges[{idx}];
                            r.len &= {mask};
                            bpf_probe_read_kernel(ctx->{name}, r.len, data + r.idx);
                            ctx->{name}_range = r;
                            bpf_log(\"{name} inited to %s\", ctx->{name});",
                            idx=i, name=name, mask=mask
                            )
                        } else if ty == "u32" {
                            format!(
                                "r = pranges[{}];
                                r.len &= 0x3f;
                                bpf_probe_read_kernel(buf, r.len, data + r.idx);
                                buf[r.len] = '\\0'; // this way, we don't need an if-clause
                                bpf_strtoul(buf, r.len + 1, 10, &tmp);
                                ctx->{} = tmp;
                                ctx->{}_range = r;
                                bpf_log(\"{} inited to %d\", ctx->{});",
                                i, name, name, name, name
                            )
                        } else {
                            unimplemented!("{}", ty)
                        };

                        if name == "status_code" {
                            format!("#if STATS == 1\n{}\n#endif", code)
                        } else {
                            code
                        }
                    }
                    &Variable::Range(name) => {
                        let name = sanitize_var_name(name);
                        format!("ctx->{}_range = pranges[{}];
                            bpf_log(\"{} inited to (%d, %d)\", ctx->{}_range.idx, ctx->{}_range.len);", name, i, name, name, name)
                    }
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        filter.replace_code("init", inits);

        filter
    }

    fn generate_jwt_filter(&self, idx: usize, jwt: JwtFilter) -> (Filter, String) {
        let verify_sig = "if (_validate_jwt_signature(ctx->jwt_claims, ctx->jwt_claims_range.len, ctx->jwt_sig, ctx->jwt_sig_range.len, ctx->tmp) != PR_PASS) return PR_DROP;";

        if jwt.audience.is_none() && jwt.issuer.is_none() {
            let filter = Filter::default();
            return (filter, verify_sig.to_string());
        }

        let adm_templ = "
            adm = \"{adm}\";
            adm_len = {adm_len};
            admitted = false;

            bpf_for(i, 0, claims_len-adm_len) {
                bpf_clamp_uminmax(i, 0, 3072-{adm_len});
                if (bpf_strncmp(ctx->tmp + i, adm_len, adm) == 0) {
                    admitted = true;
                    break;
                }
            }

            if (!admitted) {
                bpf_log(\"JWT admission failed\");
                return PR_DROP;
            }";

        let mut admission = String::new();
        if let Some(aud) = jwt.audience {
            let aud = format!("\\\"aud\\\":\\\"{}\\\"", aud);
            let aud_admission = adm_templ
                .replace("{adm}", &aud)
                .replace("{adm_len}", &(aud.len() - 4).to_string());
            admission.push_str(&aud_admission);
            admission.push('\n');
        }

        if let Some(iss) = jwt.issuer {
            let iss = format!("\\\"iss\\\":\\\"{}\\\"", iss);
            let iss_admission = adm_templ
                .replace("{adm}", &iss)
                .replace("{adm_len}", &(iss.len() - 4).to_string());
            admission.push_str(&iss_admission);
        }

        let mut filter = self.read_filter("jwt");
        filter.replace_code("idx", idx);
        filter.replace_code("admission", admission);

        let call = format!(
            "{}\nif (_validate_jwt_admission_{}(ctx) != PR_PASS) return PR_DROP;",
            verify_sig, idx
        );

        (filter, call)
    }

    fn generate_mutate_filter(&self, idx: usize, mutate: MutateFilter) -> (Filter, String) {
        if mutate.add.is_none() && mutate.remove.is_none() {
            let filter = Filter::default();
            return (filter, String::new());
        }

        let ctx = self.get_ctx_vars();
        let offset = |idx: &str, off: &str| {
            ctx.iter()
                .map(|v| {
                    format!(
                        "if (ctx->{name}_range.idx >= {idx}) {{
                            ctx->{name}_range.idx += {off};
                        }}",
                        name = sanitize_var_name(v.name()),
                        idx = idx,
                        off = off
                    )
                })
                .collect::<Vec<String>>()
                .join("\n")
        };

        let mut mutation = String::new();
        if let Some(remove) = mutate.remove {
            for key in remove.iter() {
                let key = sanitize_var_name(&key);
                let rmv_auth = if key == "authorization" {
                    format!(
                        "if (ctx->jwt_claims_range.len > 0) {{
                            remove_range.idx = ctx->jwt_claims_range.idx-7-{key_len};
                            remove_range.len = ctx->jwt_claims_range.len+ctx->jwt_sig_range.len+8+{key_len_crlf};
                            if (_mutate_msg(msg, remove_range, NULL, 0) < 0) {{
                                bpf_err(\"ERROR: Failed to remove {key}\");
                                return PR_DROP;
                            }}
                            ctx->done_idx -= remove_range.len;
                            {offset}
                        }}",
                        key = key,
                        key_len = key.len() + 2,
                        key_len_crlf = key.len() + 3,
                        offset=offset("remove_range.idx", "-remove_range.len")
                    )
                } else {
                    String::new()
                };

                let rmv_hdr = format!(
                    "{rmv_auth}
                    if (ctx->{key}_range.len > 0) {{
                        remove_range.idx = ctx->{key}_range.idx-{key_len};
                        remove_range.len = ctx->{key}_range.len+{key_len_crlf};
                        if (_mutate_msg(msg, remove_range, NULL, 0) < 0) {{
                            bpf_err(\"ERROR: Failed to remove {key}\");
                            return PR_DROP;
                        }}
                        ctx->done_idx -= remove_range.len;
                        {offset}
                    }}",
                    rmv_auth = rmv_auth,
                    key = key,
                    key_len = key.len() + 2,
                    key_len_crlf = key.len() + 3,
                    offset = offset("remove_range.idx", "-remove_range.len")
                );

                mutation.push_str(&rmv_hdr);
            }
        }

        if let Some(add) = mutate.add {
            for (key, val) in add.iter() {
                let new_hdr = format!("{}: {}\\r\\n", key, val);
                let hdr_len = new_hdr.len() - 2;
                let add = format!(
                    "new_hdr = \"{}\";
                        if (_mutate(msg, append_range, new_hdr, {}, is_skb) < 0) {{
                            bpf_err(\"ERROR: Failed to add %s\", new_hdr);
                            return PR_DROP;
                        }}
                        ctx->done_idx += {};",
                    new_hdr, hdr_len, hdr_len
                );
                mutation.push_str(&add);
            }
        }

        let mut filter = self.read_filter("mutate");
        filter.replace_code("idx", idx);
        filter.replace_code("mutation", mutation);

        let call = format!(
            "if (_mutate_{}(msg, ctx, is_skb) != PR_PASS) return PR_DROP;",
            idx
        );

        (filter, call)
    }

    fn generate_load_balancing(
        &self,
        idx: usize,
        lb: &LoadBalancer,
        instances: &Vec<SocketAddr>,
    ) -> (Filter, String) {
        let ring_len = match lb {
            LoadBalancer::Ring(lb) => lb.size,
        };

        let mut filter = self.read_filter("lb");
        filter.replace_code("idx", idx);
        filter.replace_defs("idx", idx);

        let hashes_per_instance = ring_len / instances.len();
        let ring = instances
            .iter()
            .map(|addr| {
                let ip4: u32 = addr.ip().try_into_ne_octets().unwrap();
                format!("{{.ip4 = {}, .port = {}}},", ip4, addr.port()).repeat(hashes_per_instance)
            })
            .collect::<Vec<String>>()
            .join("");

        let ring_len = hashes_per_instance * instances.len(); // to avoid rounding errors
        filter.replace_code("ring_len", ring_len);
        filter.replace_defs("ring", ring);

        let call = format!("_load_balance_{}(ctx, ikey);", idx);

        (filter, call)
    }

    fn generate_ds_routes(&self) -> Vec<Route> {
        self.config
            .routes
            .iter()
            .enumerate()
            .map(|(idx, route)| {
                let path_condition = if let Some(path) = &route.pattern.path {
                    if path == "*" {
                        "true".to_string()
                    } else {
                        format!(
                            "bpf_strncmp(ctx->path, {}, \"{} \") == 0",
                            path.len() + 1,
                            path
                        )
                    }
                } else {
                    "true".to_string()
                };

                let header_condition = if let Some(headers) = &route.pattern.headers {
                    headers
                        .iter()
                        .map(|(key, val)| {
                            format!("bpf_strncmp(ctx->{}, {}, \"{}\") == 0", key, val.len(), val)
                        })
                        .collect::<Vec<String>>()
                        .join(" && ")
                } else {
                    "true".to_string()
                };

                let else_if = if idx > 0 { "else " } else { "" };
                let cond = format!(
                    "{}if ({} && {}) {{
                    if (route_ds_{}(msg, ctx, ikey, is_skb) != PR_PASS) {{
                            bpf_err(\"ERROR: route_{} failed.\");
                        }}
                    }}",
                    else_if, path_condition, header_condition, idx, idx
                );

                let (mut filters, calls) = route
                    .filters
                    .clone()
                    .into_iter()
                    .map(|f| match f {
                        CFilter::Jwt(f) => Some(self.generate_jwt_filter(idx, f)),
                        CFilter::Mutate(f) => Some(self.generate_mutate_filter(idx, f)),
                    })
                    .filter(|f| f.is_some())
                    .map(|f| f.unwrap())
                    .collect::<(Vec<Filter>, Vec<String>)>();

                let host = self.config.resolve_host(&route.dest).unwrap();
                let route_code = match (host.instances.len(), host.load_balancer) {
                    (0, _) => unreachable!(),
                    (1, _) => {
                        let addr = host.instances[0];
                        let ip4: u32 = addr.ip().try_into_ne_octets().unwrap();
                        format!(
                            "ctx->dest.ip4 = {};
                        ctx->dest.port = {};",
                            ip4,
                            addr.port()
                        )
                    }
                    (_, Some(lb)) => {
                        let (filter, call) =
                            self.generate_load_balancing(idx, &lb, &host.instances);
                        filters.push(filter);
                        call
                    }
                    (_, None) => {
                        panic!(
                            "{} has multiple instances without a load balancer specified",
                            host.name
                        );
                    }
                };

                let chain = format!(
                    "
                    {}
                    {}
                ",
                    calls.join("\n"),
                    route_code
                );

                let mut route = self.read_filter("route");
                route.replace_code("idx", idx);
                route.replace_code("route", chain);

                filters.push(route);

                Route { cond, filters }
            })
            .collect::<Vec<Route>>()
    }

    fn generate_rbac(&self, policies: &Vec<Policy>) -> Filter {
        let mut filter = self.read_filter("rbac");
        let policies = policies
            .iter()
            .map(|p| {
                let method_cond = p
                    .method
                    .as_ref()
                    .map(|method| {
                        format!(
                            "bpf_strncmp(ctx->method, {}, \"{}\") == 0",
                            method.len(),
                            method
                        )
                    })
                    .unwrap_or(String::from("true"));

                let path_cond = p
                    .path
                    .as_ref()
                    .map(|path| {
                        format!("bpf_strncmp(ctx->path, {}, \"{}\") == 0", path.len(), path)
                    })
                    .unwrap_or(String::from("true"));

                let dest_ip4_cond = p
                    .dest_ip4
                    .as_ref()
                    .map(|ip4| format!("ctx->dest.ip4 == {}", ip4.try_into_ne_octets().unwrap()))
                    .unwrap_or(String::from("true"));

                let dest_port_cond = p
                    .dest_port
                    .as_ref()
                    .map(|port| format!("ctx->dest.port == {}", port))
                    .unwrap_or(String::from("true"));

                let src_ip4_cond = p
                    .src_ip4
                    .as_ref()
                    .map(|ip4| format!("ikey->local.ip4 == {}", ip4.try_into_ne_octets().unwrap()))
                    .unwrap_or(String::from("true"));

                let hdrs_cond = p
                    .headers
                    .as_ref()
                    .map(|hdrs| {
                        let cond = hdrs
                            .iter()
                            .map(|(key, val)| {
                                format!(
                                    "bpf_strncmp(ctx->{}, {}, \"{}\") == 0",
                                    sanitize_var_name(key),
                                    val.len(),
                                    val
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(" && ");

                        format!("({})", cond)
                    })
                    .unwrap_or(String::from("true"));

                let action = if p.allow {
                    format!(
                        "bpf_log(\"RBAC: {}\");
                    bpf_stats_add(http_rbac_allowed, 1);
                    return PR_PASS;",
                        p.name
                    )
                } else {
                    format!(
                        "bpf_log(\"RBAC {} denied\");
                    bpf_stats_add(http_rbac_denied, 1);
                    return SK_DROP;",
                        p.name
                    )
                };

                format!(
                    "if (({}) && ({}) && ({}) && ({}) && ({}) && ({})) {{
                       {}
                    }}",
                    method_cond,
                    path_cond,
                    dest_ip4_cond,
                    dest_port_cond,
                    src_ip4_cond,
                    hdrs_cond,
                    action
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        let no_match_action = if policies.is_empty() {
            String::from("return PR_PASS;")
        } else {
            format!(
                "bpf_stats_add(http_rbac_denied, 1);
                return PR_DROP;"
            )
        };

        filter.replace_code("policies", policies);
        filter.replace_code("no_match_action", no_match_action);

        filter
    }

    fn generate_match(&self, downstream: &Vec<Route>, upstream: &Vec<Route>) -> Filter {
        let mut filter = self.read_filter("match");
        let mut downstream = downstream
            .iter()
            .map(|r| r.cond.clone())
            .collect::<Vec<String>>()
            .join("\n");

        let no_match = format!("else {{ bpf_err(\"ERROR: No match\"); }}");
        downstream.push_str(&no_match);

        let upstream = upstream
            .iter()
            .map(|r| r.cond.clone())
            .collect::<Vec<String>>()
            .join("\n");

        filter.replace_code("downstream", downstream);
        filter.replace_code("upstream", upstream);

        filter
    }

    fn generate_filters(&self) -> Vec<Filter> {
        let ctx = self.get_ctx_vars();
        let ctx = self.generate_ctx(ctx);

        let rbac = self.generate_rbac(&self.config.policies);
        let ds_routes = self.generate_ds_routes();
        let us_routes = Vec::new();
        let match_reqs = self.generate_match(&ds_routes, &us_routes);

        let mut filters = Vec::new();
        filters.push(ctx);
        filters.push(rbac);

        for route in &ds_routes {
            for filter in &route.filters {
                filters.push(filter.clone());
            }
        }

        filters.push(match_reqs);

        filters
    }

    pub fn generate<P: AsRef<Path>>(&self, base: P, out: P) {
        let base = fs::read_to_string(base).expect("Failed to read base file");
        let out = out.as_ref().to_string_lossy().into_owned();
        let filters = self.generate_filters();

        let defs = filters
            .iter()
            .map(|f| f.defs.clone())
            .collect::<Vec<String>>()
            .join("\n");
        let prog = base.replace("{{DEFS}}", &defs);

        let code = filters
            .iter()
            .map(|f| f.code.clone())
            .collect::<Vec<String>>()
            .join("\n");
        let prog = prog.replace("{{FILTERS}}", &code);

        let mut file = File::create(&out).expect("Failed to create src file");
        file.write_all(prog.as_bytes())
            .expect("Failed to write to src file");
    }

    pub fn get_ctx_vars(&self) -> Vec<Variable> {
        let mut ctx: Vec<Variable> = Vec::new();
        let mut insert = |var: Variable| {
            if ctx.iter().any(|v| {
                v.name() == var.name() && (v.is_buffer() || v.is_buffer() == var.is_buffer())
            }) {
                return;
            }

            ctx.push(var.clone());
        };

        let mut max_path_len = 16;
        let mut auth = false;
        for route in &self.config.routes {
            if let Some(path) = &route.pattern.path {
                // +12 because we're also matching HTTP/1.1\r\n in the path
                max_path_len = max_path_len.max(path.len() + 12)
            }

            if let Some(headers) = &route.pattern.headers {
                for (key, val) in headers {
                    insert(Variable::buffer(key, "char", Some(val.len())));
                }
            }

            for filter in &route.filters {
                match filter {
                    CFilter::Jwt(_) => {
                        auth = true;
                    }
                    CFilter::Mutate(mutate) => {
                        if let Some(remove) = mutate.remove.as_ref() {
                            for key in remove {
                                insert(Variable::range(key));
                            }
                        }
                    }
                }
            }
        }

        insert(Variable::buffer("method", "char", Some(7)));
        insert(Variable::buffer("path", "char", Some(max_path_len)));
        insert(Variable::buffer("status_code", "u32", None));
        insert(Variable::buffer("content-length", "u32", None));

        if auth {
            insert(Variable::buffer("jwt_claims", "char", Some(4095)));
            insert(Variable::buffer("jwt_sig", "char", Some(63)));
        }

        ctx
    }
}
