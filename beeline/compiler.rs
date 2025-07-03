use common::{config, net::TryIntoRawOctets, Config};
use std::{
    fs::{self, File},
    io::Write,
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
    base: String,
    out: String,
}

fn sanitize_var_name(var: &str) -> String {
    var.replace("-", "_")
}

impl Compiler {
    pub fn new<P: AsRef<Path>>(base: P, out: P) -> Self {
        Compiler {
            base: fs::read_to_string(base).expect("Failed to read base file"),
            out: out.as_ref().to_string_lossy().into_owned(),
        }
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

    fn generate_ctx(&self, vars: Vec<(String, String, Option<usize>)>) -> Filter {
        let mut filter = self.read_filter("ctx");
        let vars = vars
            .iter()
            .map(|(name, ty, size)| (sanitize_var_name(name), ty, size))
            .collect::<Vec<_>>();

        let var_defs = vars
            .iter()
            .map(|(name, ty, size)| {
                if **ty == "char" {
                    format!("char {}[{}];", name, size.unwrap())
                } else {
                    format!("{} {};", ty, name)
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        filter.replace_defs("vars", var_defs);

        let range_defs = vars
            .iter()
            .map(|(name, _, _)| format!("struct prange {}_range;", name))
            .collect::<Vec<String>>()
            .join("\n");
        filter.replace_defs("ranges", range_defs);

        let inits = vars
            .iter()
            .enumerate()
            .map(|(i, (name, ty, _))| {
                // TODO: let the initialization fail if len < size
                if **ty == "char" {
                    format!(
                        "r = pranges[{}];
                    r.len &= 0xfff;
                    bpf_probe_read_kernel(ctx->{}, r.len, data + r.idx);
                    ctx->{}_range = r;
                    bpf_log(\"{} inited to %s\", ctx->{});",
                        i, name, name, name, name
                    )
                } else {
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
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        filter.replace_code("init", inits);

        filter
    }

    fn generate_jwt_filter(
        &self,
        idx: usize,
        aud: Option<&String>,
        iss: Option<&String>,
    ) -> (Filter, String) {
        if aud.is_none() && iss.is_none() {
            return (Filter::default(), String::new());
        }

        let adm_templ = "
            adm = \"{adm}\";
            adm_len = {adm_len};
            admitted = false;

            j = 0;
            bpf_for(i, 0, claims_len) {{
                if (ctx->tmp[i] == adm[j]) {{
                    j++;
                    if (j == adm_len) {{
                        admitted = true;
                        break;
                    }}
                }}
                else if (ctx->tmp[i] != ' ') {{
                    j = 0;
                }}
            }}

            if (!admitted) {{
                bpf_log(\"JWT admission failed\");
                return PR_DROP;
            }}";

        let mut admission = String::new();
        if let Some(aud) = aud {
            let aud = format!("\\\"audience\\\":\\\"{}\\\"", aud);
            let aud_admission = adm_templ
                .replace("{adm}", &aud)
                .replace("{adm_len}", &(aud.len() - 4).to_string());
            admission.push_str(&aud_admission);
            admission.push('\n');
        }

        if let Some(iss) = iss {
            let iss = format!("\\\"issuer\\\":\\\"{}\\\"", iss);
            let iss_admission = adm_templ
                .replace("{adm}", &iss)
                .replace("{adm_len}", &(iss.len() - 4).to_string());
            admission.push_str(&iss_admission);
        }

        let mut filter = self.read_filter("jwt");
        filter.replace_code("idx", idx);
        filter.replace_code("admission", admission);

        let call = format!(
            "if (_validate_jwt_signature(ctx->jwt_claims, ctx->jwt_claims_range.len, ctx->jwt_sig, ctx->jwt_sig_range.len, ctx->tmp) != PR_PASS) return PR_DROP;
        if (_validate_jwt_admission_{}(ctx) != PR_PASS) return PR_DROP;",
            idx
        );

        (filter, call)
    }

    fn generate_ds_routes(&self, config: &Config) -> Vec<Route> {
        config
            .routes
            .iter()
            .enumerate()
            .map(|(idx, route)| {
                let path_condition = if let Some(path) = &route.pattern.path {
                    if path == "*" {
                        "true".to_string()
                    } else {
                        format!("bpf_strncmp(ctx->path, {}, \"{}\") == 0", path.len(), path)
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

                let addr = config.select_backend_instance(&route.dest).unwrap();
                let ip4: u32 = addr.ip().try_into_ne_octets().unwrap();

                let cond = format!(
                    "if ({} && {}) {{
                        if (route_ds_{}(ikey, ctx) != PR_PASS) {{
                            bpf_err(\"ERROR: route_{} failed.\");
                        }}
                    }}",
                    path_condition, header_condition, idx, idx
                );

                let (mut filters, calls) = route
                    .filters
                    .iter()
                    .map(|f| match f {
                        config::Filter::Jwt(f) => Some(self.generate_jwt_filter(
                            idx,
                            f.audience.as_ref(),
                            f.issuer.as_ref(),
                        )),
                        config::Filter::Mutate(f) => unimplemented!("mutate"),
                    })
                    .filter(|f| f.is_some())
                    .map(|f| f.unwrap())
                    .collect::<(Vec<Filter>, Vec<String>)>();

                let chain = format!(
                    "
                    {}
                    ctx->dest.ip4 = {};
                    ctx->dest.port = {};
                ",
                    calls.join("\n"),
                    ip4,
                    addr.port()
                );

                let mut route = self.read_filter("route");
                route.replace_code("idx", idx);
                route.replace_code("route", chain);

                filters.push(route);

                Route { cond, filters }
            })
            .collect::<Vec<Route>>()
    }

    fn generate_chain(&self, downstream: &Vec<Route>, upstream: &Vec<Route>) -> Filter {
        let mut filter = self.read_filter("chain");
        let downstream = downstream
            .iter()
            .map(|r| r.cond.clone())
            .collect::<Vec<String>>()
            .join("\n");

        let upstream = upstream
            .iter()
            .map(|r| r.cond.clone())
            .collect::<Vec<String>>()
            .join("\n");

        filter.replace_code("downstream", downstream);
        filter.replace_code("upstream", upstream);

        filter
    }

    fn generate_filters(&self, config: Config) -> Vec<Filter> {
        let mut ctx = Vec::new();

        ctx.push(("path".to_string(), "char".to_string(), Some(4096)));
        ctx.push(("content_length".to_string(), "u32".to_string(), None));

        let mut auth = false;

        for route in &config.routes {
            if let Some(headers) = &route.pattern.headers {
                for (key, _) in headers {
                    ctx.push((key.to_string(), "char".to_string(), Some(4096)));
                }
            }
            for filter in &route.filters {
                if filter.is_jwt() {
                    auth = true;
                }
            }
        }

        if auth {
            ctx.push(("jwt_claims".to_string(), "char".to_string(), Some(4096)));
            ctx.push(("jwt_sig".to_string(), "char".to_string(), Some(4096)));
        }

        let ctx = self.generate_ctx(ctx);
        let ds_routes = self.generate_ds_routes(&config);
        let us_routes = Vec::new();
        let chain = self.generate_chain(&ds_routes, &us_routes);

        let mut filters = Vec::new();
        filters.push(ctx);

        for route in &ds_routes {
            for filter in &route.filters {
                filters.push(filter.clone());
            }
        }

        filters.push(chain);

        filters
    }

    pub fn generate(&self, config: Config) {
        let base = self.base.clone();
        let filters = self.generate_filters(config);

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

        let mut file = File::create(&self.out).expect("Failed to create src file");
        file.write_all(prog.as_bytes())
            .expect("Failed to write to src file");
    }
}
