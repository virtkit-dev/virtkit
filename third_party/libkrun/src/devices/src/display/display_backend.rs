use krun_display::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew, Rect, ResourceFormat,
};

pub struct NoopDisplayBackend;

impl DisplayBackendNew<()> for NoopDisplayBackend {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl DisplayBackendBasicFramebuffer for NoopDisplayBackend {
    fn configure_scanout(
        &mut self,
        _scanout_id: u32,
        _display_width: u32,
        _display_height: u32,
        _width: u32,
        _height: u32,
        _format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn disable_scanout(&mut self, _scanout_id: u32) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn alloc_frame(&mut self, _scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn present_frame(
        &mut self,
        _scanout_id: u32,
        _frame_id: u32,
        _rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }
}
