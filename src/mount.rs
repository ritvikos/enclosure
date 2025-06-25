use crate::{
    config::{FileOp, MountCommand, MountCommands, MountOp, SpecialMount, SystemOp},
    context::GlobalContext,
    jail::Jail,
    privsep::{Supervisor, Worker, privsep},
    utils,
};
use anyhow::Result;

impl Jail<'_> {
    pub fn handle_mounts(&self) -> Result<()> {
        let context = GlobalContext::current();

        if context.setuid() {
            privsep::<MountCommand, _, _>(
                |worker| self.mount_worker(worker),
                |supervisor| self.mount_supervisor(supervisor),
            )?;
        }

        Ok(())
    }

    fn mount_supervisor(&self, supervisor: Supervisor<MountCommand>) -> Result<()> {
        println!("[PARENT SUPERVISOR]: Waiting for Commands");

        supervisor.listen(self.config, |_, cmd| match cmd {
            MountCommand::Mount(op) => match op {
                MountOp::Bind {
                    source,
                    target,
                    options,
                } => {
                    todo!()
                }

                MountOp::Overlay {
                    lowerdir,
                    upperdir,
                    workdir,
                    target,
                    mode,
                } => {
                    todo!()
                }

                MountOp::Special(special_mount) => match special_mount {
                    SpecialMount::Proc(path_buf) => {
                        todo!()
                    }
                    SpecialMount::Dev(path_buf) => {
                        todo!()
                    }
                    SpecialMount::Tmpfs {
                        target,
                        size_kb,
                        mode,
                    } => {
                        todo!()
                    }
                    SpecialMount::Mqueue(path_buf) => {
                        todo!()
                    }
                    SpecialMount::OverlaySource {
                        lowerdir,
                        upperdir,
                        workdir,
                    } => {
                        todo!()
                    }
                },
            },

            MountCommand::File(op) => match op {
                FileOp::CreateDir(path_buf) => {
                    todo!()
                }
                FileOp::CreateFile { fd, dest } => {
                    todo!()
                }
                FileOp::CreateBindFile {
                    source,
                    dest,
                    readonly,
                } => {
                    todo!()
                }
                FileOp::CreateSymlink { link_path, target } => {
                    todo!()
                }
                FileOp::RemountReadOnly(path_buf) => {
                    todo!()
                }
            },

            MountCommand::System(op) => match op {
                SystemOp::SetHostname(name) => {
                    todo!()
                }
                SystemOp::Chmod { path, mode } => {
                    todo!()
                }
            },
        })?;

        Ok(())
    }

    fn mount_worker(&self, worker: Worker<MountCommand>) -> Result<()> {
        println!("[CHILD WORKER]: Sending Commands");

        // TODO: drop privileges

        let mount_config = self.config.mount.clone();
        let commands = MountCommands::from(mount_config);

        for command in commands.iter() {
            // worker.send(command)?;

            match command {
                MountCommand::Mount(op) => match op {
                    MountOp::Bind {
                        source,
                        target,
                        options,
                    } => {
                        if target.is_dir() {
                            utils::ensure_directory(target, 0755)?;
                        } else if target.is_file() {
                            utils::ensure_file(target, 0444)?;
                        }

                        // TODO: Handle race condition
                    }

                    MountOp::Overlay {
                        lowerdir,
                        upperdir,
                        workdir,
                        target,
                        mode,
                    } => {
                        todo!()
                    }

                    MountOp::Special(mount) => match mount {
                        SpecialMount::Proc(path_buf) => todo!(),
                        SpecialMount::Dev(path_buf) => todo!(),
                        SpecialMount::Tmpfs {
                            target,
                            size_kb,
                            mode,
                        } => todo!(),
                        SpecialMount::Mqueue(path_buf) => todo!(),
                        SpecialMount::OverlaySource {
                            lowerdir,
                            upperdir,
                            workdir,
                        } => todo!(),
                    },
                },

                MountCommand::File(op) => match op {
                    FileOp::CreateDir(path_buf) => todo!(),
                    FileOp::CreateFile { fd, dest } => todo!(),
                    FileOp::CreateBindFile {
                        source,
                        dest,
                        readonly,
                    } => todo!(),
                    FileOp::CreateSymlink { link_path, target } => todo!(),
                    FileOp::RemountReadOnly(path_buf) => todo!(),
                },

                MountCommand::System(op) => match op {
                    SystemOp::SetHostname(name) => todo!(),
                    SystemOp::Chmod { path, mode } => todo!(),
                },
            }
        }

        Ok(())
    }
}
