    
    def merge(self):
        try: 
            self.load()
            if self.subset:
                self.sbom.merge(self.subset)
                self.subset = None
        except FileNotFoundError as e:
            logger.error(f"No file loaded, nothing to merge.")