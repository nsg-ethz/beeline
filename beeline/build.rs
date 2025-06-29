use common::{config::envoy, Config};
use libbpf_cargo::SkeletonBuilder;
use std::{
    collections::HashMap,
    env,
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
struct Filter {
    name: Option<String>,
    defs: String,
    code: String,
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

        let sig = text.split_once("__noinline enum pr_action");
        let name = if let Some(sig) = sig {
            Some(
                sig.1
                    .split_once("(")
                    .expect("Invalid filter signature")
                    .0
                    .trim()
                    .to_string(),
            )
        } else {
            None
        };

        Filter {
            name,
            defs: segs[0].into(),
            code: segs[1].into(),
        }
    }
}

struct Compiler {
    base: String,
    out: String,
}

fn sanitize_var_name(var: &str) -> String {
    var.replace("-", "_")
}

impl Compiler {
    fn new<P: AsRef<Path>>(base: P, out: P) -> Self {
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

    fn generate_ctx(&self, vars: Vec<(&str, &str, Option<usize>)>) -> Filter {
        let mut filter = self.read_filter("ctx");
        let vars = vars
            .iter()
            .map(|(name, ty, size)| (sanitize_var_name(name), ty, size))
            .collect::<Vec<_>>();

        let var_defs = vars
            .iter()
            .map(|(name, ty, size)| {
                if **ty == "str" {
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
                if **ty == "str" {
                    format!(
                        "r = pranges[{}];
                    r.len &= 0xfff;
                    bpf_probe_read_kernel(ctx->{}, r.len, data + r.idx);
                    ctx->{}_range = r;",
                        i, name, name
                    )
                } else {
                    format!(
                        "r = pranges[{}];
                        r.len &= 0x3f;
                        bpf_probe_read_kernel(buf, r.len, data + r.idx);
                        buf[r.len] = '\\0'; // this way, we don't need an if-clause
                        bpf_strtoul(buf, r.len + 1, 10, &tmp);
                        ctx->{} = tmp;
                        ctx->{}_range = r;",
                        i, name, name
                    )
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        filter.replace_code("init", inits);

        filter
    }

    fn generate_jwt_filter(&self, key: &str) -> Filter {
        let mut filter = self.read_filter("jwt");
        filter.replace_code("key", key);
        filter.replace_code("key_len", key.len());

        filter
    }

    fn generate_frwd_ds_filter(&self) -> Filter {
        let mut frwd = self.read_filter("frwd_ds");

        frwd
    }

    fn generate_post_frwd_ds_filter(&self) -> Filter {
        let mut filter = self.read_filter("post_frwd_ds");

        filter
    }

    fn generate_frwd_us_filter(&self) -> Filter {
        let mut frwd = self.read_filter("frwd_us");

        frwd
    }

    fn generate_post_frwd_us_filter(&self) -> Filter {
        let mut filter = self.read_filter("post_frwd_us");
        filter.replace_code("service_proxy_port", "3333");

        filter
    }

    fn generate_chain(&self, downstream: &Vec<Filter>, upstream: &Vec<Filter>) -> Filter {
        let mut filter = self.read_filter("chain");
        let downstream = downstream
            .iter()
            .map(|f| {
                format!(
                    "if ({}(ikey, ctx) != PR_PASS) {{
                    bpf_err(\"ERROR: {} failed.\");
                }}",
                    f.name.as_ref().unwrap(),
                    f.name.as_ref().unwrap()
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        let upstream = upstream
            .iter()
            .map(|f| {
                format!(
                    "if ({}(ikey, ctx) != PR_PASS) {{
                    bpf_err(\"ERROR: {} failed.\");
                }}",
                    f.name.as_ref().unwrap(),
                    f.name.as_ref().unwrap()
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        filter.replace_code("downstream", downstream);
        filter.replace_code("upstream", upstream);

        filter
    }

    fn generate_filters(&self, config: Config) -> Vec<Filter> {
        let mut downstream = Vec::new();
        let mut upstream = Vec::new();
        let mut ctx = Vec::new();

        for (var, ty) in config.patterns.http.iter() {
            let size = if ty == "str" { Some(1024) } else { None };
            ctx.push((var.as_str(), ty.as_str(), size))
        }
        ctx.push(("content_length", "u32", None));

        // for auth in config.auths {
        //     let filter = self.generate_jwt_filter(&auth.secret);
        //     downstream.push(filter);
        //     ctx.push(("jwt_claims", "char", Some(4096)));
        //     ctx.push(("jwt_sig", "char", Some(64)));
        // }

        // at the end of the chain we have to add the forwarding filters
        // downstream.push(self.generate_frwd_ds_filter());
        // upstream.push(self.generate_frwd_us_filter());

        let ctx = self.generate_ctx(ctx);
        let chain = self.generate_chain(&downstream, &upstream);

        let mut filters = Vec::new();
        // let mut filters = downstream
        //     .into_iter()
        //     .chain(upstream.into_iter())
        //     .collect::<Vec<Filter>>();
        filters.push(ctx);
        filters.push(chain);
        // filters.push(self.generate_post_frwd_ds_filter());
        // filters.push(self.generate_post_frwd_us_filter());

        filters
    }

    fn generate(&self, config: Config) {
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

fn main() {
    let bpf_skel = std::env::var("BPF_SKEL").unwrap_or("0".to_string());
    let bpf_skel: bool = match bpf_skel.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        _ => false,
    };
    println!("cargo:rerun-if-env-changed=BPF_SKEL");

    let bpf_profile = std::env::var("BPF_PROFILE").unwrap_or("0".to_string());
    println!("cargo:rerun-if-env-changed=BPF_PROFILE");

    let log_level = std::env::var("RUST_LOG").unwrap_or("error".to_string());
    let log_level: u32 = match log_level.to_lowercase().as_str() {
        "debug" => 2,
        "trace" => 2,
        _ => 1,
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    let sm = std::env::var("SM_APP").unwrap_or("mb".to_string());
    let sm: u32 = match sm.to_lowercase().as_str() {
        "sn" => 1,
        "ms" => 2,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=SM_APP");

    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let root_dir = PathBuf::from(&manifest_dir).join("..");
    let target_dir = root_dir.join("target").join("bpf");
    let base = PathBuf::from(&manifest_dir).join("src/bpf/base.bpf.c");
    let filter_dir = PathBuf::from(&manifest_dir).join("src/bpf/filter/");
    let out = PathBuf::from(&target_dir).join("proxy.bpf.c");

    println!("cargo:rerun-if-changed={:?}", base);
    println!("cargo:rerun-if-changed={:?}", filter_dir);

    match fs::create_dir(&target_dir) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
    .expect("Failed to create target/bpf");

    let config = env::var_os("CONFIG").expect("CONFIG must be set in build script");
    let config = PathBuf::from(&root_dir).join(config);
    let config = std::fs::File::open(config).expect("Failed to open config file");
    let config: envoy::Config =
        serde_yaml::from_reader(&config).expect("Failed to parse Envoy config");
    let config = Config::from(config);

    let compiler = Compiler::new(&base, &out);
    compiler.generate(config);

    let mut builder = SkeletonBuilder::new();
    let builder = builder.source(&out).clang_args([
        OsStr::new("-D"),
        OsStr::new(format!("LOG_LEVEL={log_level}").as_str()),
        OsStr::new("-D"),
        OsStr::new(format!("BPF_PROFILE={bpf_profile}").as_str()),
        OsStr::new("-D"),
        OsStr::new(format!("SM_APP={sm}").as_str()),
        OsStr::new("-I"),
        OsStr::new("../include"),
    ]);

    if bpf_skel {
        builder.build_and_generate(&out).unwrap();
    } else {
        builder.build().unwrap();
    }
}
