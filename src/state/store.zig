// store — persistent state facade
//
// this file now exposes the stable state-store API while the
// implementations live in smaller domain modules under `state/store/`.

const common = @import("store/common.zig");

pub const StoreError = common.StoreError;

pub const ContainerRecord = @import("store/containers.zig").ContainerRecord;
pub const ImageRecord = @import("store/images.zig").ImageRecord;
pub const BuildCacheEntry = @import("store/cache.zig").BuildCacheEntry;
pub const NetworkPolicyRecord = @import("store/services.zig").NetworkPolicyRecord;
pub const DeploymentRecord = @import("store/deployments.zig").DeploymentRecord;
pub const TrainingJobRecord = @import("store/training.zig").TrainingJobRecord;
pub const CheckpointRecord = @import("store/training.zig").CheckpointRecord;

pub const initTestDb = common.initTestDb;
pub const deinitTestDb = common.deinitTestDb;
pub const getDb = common.getDb;
pub const closeDb = common.closeDb;
pub const openDb = common.openDb;

pub const save = @import("store/containers.zig").save;
pub const load = @import("store/containers.zig").load;
pub const findByHostname = @import("store/containers.zig").findByHostname;
pub const remove = @import("store/containers.zig").remove;
pub const listIds = @import("store/containers.zig").listIds;
pub const updateStatus = @import("store/containers.zig").updateStatus;
pub const updateNetwork = @import("store/containers.zig").updateNetwork;
pub const listAppContainerIds = @import("store/containers.zig").listAppContainerIds;
pub const findAppContainer = @import("store/containers.zig").findAppContainer;
pub const listAll = @import("store/containers.zig").listAll;

pub const saveImage = @import("store/images.zig").saveImage;
pub const loadImage = @import("store/images.zig").loadImage;
pub const findImage = @import("store/images.zig").findImage;
pub const listImages = @import("store/images.zig").listImages;
pub const removeImage = @import("store/images.zig").removeImage;

pub const lookupBuildCache = @import("store/cache.zig").lookupBuildCache;
pub const storeBuildCache = @import("store/cache.zig").storeBuildCache;
pub const listBuildCacheDigests = @import("store/cache.zig").listBuildCacheDigests;

pub const registerServiceName = @import("store/services.zig").registerServiceName;
pub const unregisterServiceName = @import("store/services.zig").unregisterServiceName;
pub const lookupServiceNames = @import("store/services.zig").lookupServiceNames;
pub const addNetworkPolicy = @import("store/services.zig").addNetworkPolicy;
pub const removeNetworkPolicy = @import("store/services.zig").removeNetworkPolicy;
pub const listNetworkPolicies = @import("store/services.zig").listNetworkPolicies;
pub const getServicePolicies = @import("store/services.zig").getServicePolicies;

pub const saveDeployment = @import("store/deployments.zig").saveDeployment;
pub const getDeployment = @import("store/deployments.zig").getDeployment;
pub const listDeployments = @import("store/deployments.zig").listDeployments;
pub const updateDeploymentStatus = @import("store/deployments.zig").updateDeploymentStatus;
pub const getLatestDeployment = @import("store/deployments.zig").getLatestDeployment;
pub const getLastSuccessfulDeployment = @import("store/deployments.zig").getLastSuccessfulDeployment;

pub const saveTrainingJob = @import("store/training.zig").saveTrainingJob;
pub const updateTrainingJobState = @import("store/training.zig").updateTrainingJobState;
pub const incrementTrainingJobRestarts = @import("store/training.zig").incrementTrainingJobRestarts;
pub const updateTrainingJobGpus = @import("store/training.zig").updateTrainingJobGpus;
pub const findTrainingJob = @import("store/training.zig").findTrainingJob;
pub const getTrainingJob = @import("store/training.zig").getTrainingJob;
pub const saveCheckpoint = @import("store/training.zig").saveCheckpoint;
pub const getLatestCheckpoint = @import("store/training.zig").getLatestCheckpoint;
pub const listCheckpoints = @import("store/training.zig").listCheckpoints;
pub const deleteCheckpoint = @import("store/training.zig").deleteCheckpoint;
